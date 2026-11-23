package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"chameleon/shared"
)

// coverRootFiles are the top-level pages a small static site serves. The
// nginx frontend publishes the same set (stealth_components/tls.py).
var coverRootFiles = map[string]string{
	"/":            "index.html",
	"/index.html":  "index.html",
	"/robots.txt":  "robots.txt",
	"/favicon.ico": "favicon.ico",
}

func newCoverHandler(siteDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if name, ok := coverRootFiles[r.URL.Path]; ok {
			http.ServeFile(w, r, siteDir+"/"+name)
			return
		}
		notFoundHandler(w, r)
	})
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(siteDir))))
	return mux
}

func main() {
	logState("server", "starting Chameleon Server v2")

	// 1. Load configuration
	cfg, err := LoadServerConfig("server_config.json")
	if err != nil {
		fatalOperationalFailure("server", "configuration load failed", err)
	}

	// Auto-generate PSK if empty
	if cfg.PSKKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fatalOperationalFailure("server", "credential generation failed", err)
		}
		cfg.PSKKey = hex.EncodeToString(key)
		logState("server", "generated a new installation credential")
		if err := SaveServerConfig("server_config.json", cfg); err != nil {
			fatalOperationalFailure("server", "configuration save failed", err)
		}
	}

	logState("server", "configuration loaded")
	configureSessionLimits(cfg.MaxConnections, cfg.MaxRequestsPerSession, cfg.MaxSessionsPerSource)

	// 2. Initialize cryptography
	pskBytes, err := hex.DecodeString(cfg.PSKKey)
	if err != nil {
		fatalOperationalFailure("server", "installation credential is invalid", err)
	}

	authKey, _ := hex.DecodeString(cfg.ClientAuthKey)
	cryptoSessions := newCryptoSessionManager(authKey)
	if err := cryptoSessions.setCredentialNetwork(cfg.TunnelCIDR); err != nil {
		fatalOperationalFailure("server", "mobile credential network is invalid", err)
	}
	cryptoSessions.credentialsFile = cfg.MobileClientsFile
	if err := cryptoSessions.refreshCredentials(); err != nil {
		fatalOperationalFailure("server", "mobile registry unavailable", err)
	}
	credentialStop := make(chan struct{})
	defer close(credentialStop)
	go cryptoSessions.watchCredentials(credentialStop)
	logState("server", "cryptography initialized")

	// Start kernel TUN path for full-device tunnel routing (TCP + UDP + ICMP).
	// If unavailable, server falls back to legacy UDP relay mode.
	kernelTun, err = startKernelTunnel(cfg.TunnelName, cfg.TunnelCIDR, cfg.TunnelMTU, cfg.BlockQUICUDP443)
	if err != nil {
		if os.Getenv("CHAMELEON_NETWORK_PREPARED") == "1" {
			fatalOperationalFailure("tun", "required kernel tunnel unavailable", err)
		}
		logOperationalFailure("tun", "kernel tunnel unavailable; legacy UDP relay enabled", err)
	} else {
		logState("tun", "kernel tunnel enabled")
		startKernelTunnelReader(kernelTun)
		if cfg.PrismLinkListen != "" {
			prismLink, err = startPrismLinkServer(cfg.PrismLinkListen, cryptoSessions, kernelTun)
			if err != nil {
				fatalOperationalFailure("prismlink", "UDP listener unavailable", err)
			}
			logState("prismlink", "authenticated UDP tunnel enabled")
		}
	}

	// Initialize Cloudflare Client if configured
	if cfg.CFApiToken != "" && cfg.CFZoneID != "" && cfg.DoHDomain != "" {
		cfClient = NewCloudflareClient(cfg.CFApiToken, cfg.CFZoneID, cfg.DoHDomain)
		logState("doh-sender", "fallback transport initialized")
	}

	// 3. Create demasker
	demasker := NewDemasker(authKey)

	// 4. Setup HTTP routes
	mux := http.NewServeMux()

	// Cover website: serve static files
	siteDir := cfg.SiteDir
	if siteDir == "" {
		siteDir = "site"
	}

	mux.Handle("/", newCoverHandler(siteDir))

	// Derive route prefix deterministically from the PSK.
	// No config entry needed — both sides compute the same prefix from the shared secret.
	routePrefix := shared.DeriveRoutePrefix(pskBytes)
	routePush := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixPush)
	routePoll := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixPoll)
	routeStream := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixStream)
	routeUpload := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixUpload)
	routeSync := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixSync)

	logState("routes", "authenticated tunnel routes initialized")

	// Direct-front-end compatibility marker. Public nginx deployments still
	// provide this value to clients for their browser TLS/profile selection, but
	// nginx itself owns the externally visible handshake.
	var realityPub []byte
	pskBytes, _ = hex.DecodeString(cfg.PSKKey)
	if cfg.RealityPublicKey != "" {
		realityPub, _ = hex.DecodeString(cfg.RealityPublicKey)
		if cfg.FrontendMode == "direct" {
			logState("reality", "per-connection marker enabled")
		}
	}

	// API routes accept only keys from an active challenge/response session.
	mux.HandleFunc(routePush, SessionAuthMiddleware(cryptoSessions, handlePush(demasker)))
	mux.HandleFunc(routeUpload, SessionAuthMiddleware(cryptoSessions, handleUpload(demasker)))
	mux.HandleFunc(routePoll, SessionAuthMiddleware(cryptoSessions, handlePoll()))
	mux.HandleFunc(routeStream, SessionAuthMiddleware(cryptoSessions, handleStream()))
	mux.HandleFunc(routeSync, handleSessionSync(cryptoSessions, cfg.FrontendMode != "nginx"))
	mux.HandleFunc(shared.RouteForPrefix(routePrefix, shared.EndpointSuffixTCP), SessionAuthMiddleware(cryptoSessions, handleTCPStream()))

	// DNS tunnel route — forwards client DNS queries to upstream resolver.
	// Indistinguishable from other HTTPS API calls; prevents DNS leaks.
	upstreamDNS := cfg.UpstreamDNS
	if upstreamDNS == "" {
		upstreamDNS = "1.1.1.1:53"
	}
	routeDNS := shared.RouteForPrefix(routePrefix, shared.EndpointSuffixDNS)
	mux.HandleFunc(routeDNS, SessionAuthMiddleware(cryptoSessions, handleDNS(upstreamDNS)))
	logState("routes", "encrypted DNS forwarding initialized")

	connectHandler := ConnectSessionAuthMiddleware(cryptoSessions, handleConnect(demasker))
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connectHandler(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	// Apply application security headers. The production nginx frontend supplies
	// the externally visible TLS, HTTP/2 and Server behavior.
	handler := nginxMiddleware(rootHandler)

	// 5. TLS Configuration
	addr := net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ListenPort))

	// Check if TLS certs exist
	_, certErr := os.Stat(cfg.TLSCert)
	_, keyErr := os.Stat(cfg.TLSKey)
	if cfg.ProbeMode == "local" && (certErr != nil || keyErr != nil) {
		fatalState("reality", "IP Shield certificate is missing; refusing insecure HTTP fallback")
	}

	// In REALITY mode we still need a local TLS context for accepted Chameleon sockets.
	// If cert/key are missing, generate local self-signed files automatically.
	if (certErr != nil || keyErr != nil) && cfg.ShieldDomain != "" && len(realityPub) > 0 {
		if err := ensureTLSCertificate(cfg.TLSCert, cfg.TLSKey); err != nil {
			fatalOperationalFailure("reality", "local TLS certificate generation failed", err)
		}
		logState("reality", "local TLS certificate generated")
		_, certErr = os.Stat(cfg.TLSCert)
		_, keyErr = os.Stat(cfg.TLSKey)
	}

	var server *http.Server
	var bootstrapServer *http.Server
	var probeServer *http.Server
	var realityServer *recordShapingHTTP2Server

	if certErr == nil && keyErr == nil {
		// Production: use TLS
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			NextProtos: []string{"h2", "http/1.1"},
		}
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			fatalOperationalFailure("server", "TLS certificate load failed", err)
		}
		tlsCfg.Certificates = []tls.Certificate{certificate}

		if cfg.FrontendMode == "nginx" {
			if !isLoopbackTarget(cfg.BackendAddress) {
				fatalState("frontend", "nginx backend is not restricted to loopback")
			}
			server = &http.Server{
				Addr:              cfg.BackendAddress,
				Handler:           handler,
				ErrorLog:          privacyErrorLogger("backend"),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    256 << 10,
			}
			go func() {
				logState("frontend", "loopback backend for nginx started")
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					fatalOperationalFailure("frontend", "loopback backend failed", err)
				}
			}()
		} else {
			server = &http.Server{
				Addr:              addr,
				Handler:           handler,
				TLSConfig:         tlsCfg,
				ErrorLog:          privacyErrorLogger("http2"),
				ReadTimeout:       30 * time.Second,
				ReadHeaderTimeout: 10 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			if cfg.ProbeMode == "local" {
				if !isLoopbackTarget(cfg.ProbeTarget) {
					fatalState("reality", "local cover endpoint configuration is invalid")
				}
				probeListener, err := net.Listen("tcp", cfg.ProbeTarget)
				if err != nil {
					fatalOperationalFailure("reality", "local cover endpoint start failed", err)
				}
				probeServer = &http.Server{
					Handler:      nginxMiddleware(newCoverHandler(siteDir)),
					ErrorLog:     privacyErrorLogger("cover"),
					ReadTimeout:  15 * time.Second,
					WriteTimeout: 15 * time.Second,
					IdleTimeout:  60 * time.Second,
				}
				go func() {
					logState("reality", "local cover endpoint started")
					if err := probeServer.ServeTLS(probeListener, cfg.TLSCert, cfg.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
						fatalOperationalFailure("reality", "local cover endpoint failed", err)
					}
				}()
			}

			http2Config := &http2.Server{
				MaxConcurrentStreams:         1024,
				MaxReadFrameSize:             1 << 20,
				MaxUploadBufferPerConnection: 16 << 20,
				MaxUploadBufferPerStream:     16 << 20,
				IdleTimeout:                  120 * time.Second,
			}
			if err := http2.ConfigureServer(server, http2Config); err != nil {
				logOperationalFailure("http2", "server tuning failed", err)
			}

			if len(realityPub) > 0 {
				logState("reality", "protected listener starting")
				baseListener, err := net.Listen("tcp", addr)
				if err != nil {
					fatalOperationalFailure("reality", "protected listener start failed", err)
				}
				realityListener := NewRealityListener(
					baseListener, cfg.ShieldDomain, cfg.ProbeMode, cfg.ProbeTarget, realityPub, pskBytes,
					cfg.MaxPreAuthConnections, cfg.MaxPreAuthPerIP,
				)
				realityServer = newRecordShapingHTTP2Server(realityListener, tlsCfg, server, http2Config)

				go func() {
					if err := realityServer.Serve(); err != nil && err != http.ErrServerClosed {
						fatalOperationalFailure("reality", "protected listener failed", err)
					}
				}()
			} else {
				logState("server", "HTTPS listener starting in legacy TLS mode")
				go func() {
					if err := server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
						fatalOperationalFailure("server", "HTTPS listener failed", err)
					}
				}()
			}
		}

		// Dedicated bootstrap listener for first-run clients in REALITY setups.
		// It serves only bootstrap endpoints over TLS on a separate port.
		if cfg.BootstrapPort > 0 && cfg.BootstrapPort != cfg.ListenPort {
			bootstrapAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.BootstrapPort))
			bootstrapMux := http.NewServeMux()
			bootstrapMux.HandleFunc("/.well-known/chameleon/bootstrap", handleBootstrap(cfg))
			bootstrapMux.HandleFunc("/bootstrap", handleBootstrap(cfg))
			bootstrapHandler := nginxMiddleware(bootstrapMux)
			bootstrapServer = &http.Server{
				Addr:         bootstrapAddr,
				Handler:      bootstrapHandler,
				TLSConfig:    tlsCfg,
				ErrorLog:     privacyErrorLogger("bootstrap"),
				ReadTimeout:  15 * time.Second,
				WriteTimeout: 15 * time.Second,
				IdleTimeout:  60 * time.Second,
			}
			go func() {
				logState("bootstrap", "TLS listener started")
				if err := bootstrapServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
					logOperationalFailure("bootstrap", "listener disabled", err)
				}
			}()
		}
	} else {
		// Development: no TLS (for testing)
		logState("server", "WARNING: TLS certificates not found; development HTTP mode enabled")
		server = &http.Server{
			Addr:         addr,
			Handler:      handler,
			ErrorLog:     privacyErrorLogger("http"),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fatalOperationalFailure("server", "HTTP listener failed", err)
			}
		}()
	}

	// 6. Cleanup stale sessions periodically
	go cleanupSessions()

	// 7. Wait for shutdown signal
	logState("server", "running")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logState("server", "shutting down")
	kernelTunnelStopping.Store(true)
	if bootstrapServer != nil {
		_ = bootstrapServer.Close()
	}
	if probeServer != nil {
		_ = probeServer.Close()
	}
	if realityServer != nil {
		_ = realityServer.Close()
	}
	if prismLink != nil {
		_ = prismLink.Close()
		prismLink = nil
	}
	if kernelTun != nil {
		_ = kernelTun.Close()
		kernelTun = nil
	}
	_ = server.Close()
	sessionsMu.Lock()
	for _, s := range sessions {
		closeSession(s)
	}
	sessionsMu.Unlock()
	demasker.Stop()
	logState("server", "stopped")
}
