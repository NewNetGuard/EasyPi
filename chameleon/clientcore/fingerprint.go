package clientcore

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"chameleon/shared"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func normalizeServerName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(value, "[]")
}

// FingerprintProfile represents a browser TLS fingerprint with its matching
// HTTP headers so TLS JA3/JA4 fingerprint and User-Agent are always coherent.
type FingerprintProfile struct {
	Name string
	ID   *utls.ClientHelloID

	// SpecFactory is set for browser versions newer than the maintained uTLS
	// parrots. It must generate fresh extension objects on every dial: uTLS
	// mutates key-share, GREASE and ECH state while building the handshake.
	SpecFactory func() (utls.ClientHelloSpec, error)

	// HTTP headers tied to this browser identity.
	UA              string
	SecChUa         string // empty for Firefox / Safari (no client hints)
	SecChUaPlatform string // e.g. `"Windows"`, `"macOS"`
	SecChUaMobile   string // `?1` for mobile identities, `?0` otherwise
	AcceptLanguage  string // stable for the lifetime of the transport identity

	// TCPKeepAlive is the browser's TCP keepalive idle time and probe interval
	// on the carrier connection, visible to a passive observer whenever the
	// carrier is idle.
	TCPKeepAlive time.Duration
}

// chromeTCPKeepAlive is Chromium's TCP keepalive (idle time and interval) on
// every platform; a Chrome 158 capture showed one probe every 45 s.
const chromeTCPKeepAlive = 45 * time.Second

// profileDialer opens the carrier's TCP connection with the profile's
// keepalive. Go's default (15 s) probes three times as often as Chrome.
func profileDialer(profile FingerprintProfile) *net.Dialer {
	keepAlive := profile.TCPKeepAlive
	if keepAlive <= 0 {
		keepAlive = chromeTCPKeepAlive
	}
	return &net.Dialer{
		Timeout:         10 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: keepAlive, Interval: keepAlive},
	}
}

var helloChrome157 = utls.ClientHelloID{Client: "Chrome", Version: "157"}

// extensionTrustAnchors is Chrome's trust_anchors extension
// (draft-ietf-tls-trust-anchor-ids). Every Chrome release since 152 sends it in
// every ClientHello; uTLS v1.8.2 has no parrot that includes it.
const extensionTrustAnchors = 0xca34

// chromeTrustAnchorIDs is the trust_anchors body Chrome 157 sends: a fixed,
// sorted list of Chrome Root Store anchor IDs, byte-identical across the fresh
// Chrome 157 ClientHellos captured for this profile.
const chromeTrustAnchorIDs = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f" +
	"0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d0108" +
	"08839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c" +
	"08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d67909" +
	"0404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c" +
	"04d679090d04d679090f"

// chromeSignatureGREASE returns a random GREASE value for the signature
// algorithm list. Chrome draws it on every connection independently of the
// cipher, group, version and extension GREASE values.
func chromeSignatureGREASE() (utls.SignatureScheme, error) {
	var b [1]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, err
	}
	k := uint16(b[0] & 0x0f)
	return utls.SignatureScheme(k<<12 | k<<4 | 0x0a0a), nil
}

// chrome157ClientHelloSpec advances uTLS v1.8.2's maintained Chrome 133
// template using the stable fields observed from fresh Chrome 157 desktop
// ClientHellos. Random GREASE values, ECH material and key shares remain
// generated for every connection; captured ephemeral bytes are never copied
// into the program.
func chrome157ClientHelloSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("load Chrome 133 base spec: %w", err)
	}
	trustAnchors, err := hex.DecodeString(chromeTrustAnchorIDs)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("decode Chrome trust anchors: %w", err)
	}
	signatureGREASE, err := chromeSignatureGREASE()
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("draw signature GREASE: %w", err)
	}

	var signatureAlgorithmsFound bool
	greaseExtensions := make([]*utls.UtlsGREASEExtension, 0, 2)
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.SignatureAlgorithmsExtension:
			typed.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				signatureGREASE,
				utls.SignatureScheme(0x0904),
				utls.SignatureScheme(0x0905),
				utls.SignatureScheme(0x0906),
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}
			signatureAlgorithmsFound = true
		case *utls.UtlsGREASEExtension:
			greaseExtensions = append(greaseExtensions, typed)
		}
	}
	if !signatureAlgorithmsFound {
		return utls.ClientHelloSpec{}, errors.New("Chrome base spec has no signature_algorithms extension")
	}
	if len(greaseExtensions) != 2 {
		return utls.ClientHelloSpec{}, fmt.Errorf("Chrome base spec has %d GREASE extensions, want 2", len(greaseExtensions))
	}
	// Current Chrome sends an empty first GREASE extension and a one-byte zero
	// body in the trailing GREASE extension.
	greaseExtensions[0].Body = nil
	greaseExtensions[1].Body = []byte{0}

	// The template's trailing GREASE extension stays last; the new extension
	// goes before it and the list is shuffled again the way Chrome does, so its
	// position varies per connection like every other extension's.
	last := len(spec.Extensions) - 1
	if _, ok := spec.Extensions[last].(*utls.UtlsGREASEExtension); !ok {
		return utls.ClientHelloSpec{}, errors.New("Chrome base spec does not end with a GREASE extension")
	}
	extensions := append([]utls.TLSExtension{}, spec.Extensions[:last]...)
	extensions = append(extensions, &utls.GenericExtension{Id: extensionTrustAnchors, Data: trustAnchors}, spec.Extensions[last])
	spec.Extensions = utls.ShuffleChromeTLSExtensions(extensions)
	return spec, nil
}

func clientHelloSpecForProfile(profile FingerprintProfile) (utls.ClientHelloSpec, error) {
	if profile.SpecFactory != nil {
		return profile.SpecFactory()
	}
	return utls.UTLSIdToSpec(*profile.ID)
}

// tlsConfig returns a utls.Config appropriate for this profile.
func (fp FingerprintProfile) TLSConfig() *utls.Config {
	return &utls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

// uTLS v1.8.2's newest maintained browser parrot is Chrome 133. Chameleon keeps
// a small reviewed delta for Chrome 157 instead of forking uTLS or embedding a
// Chromium runtime. Desktop and mobile identities remain separate so their HTTP
// headers cannot contradict the shared TLS profile.
var desktopFingerprintProfiles = []FingerprintProfile{
	{
		Name:            "Chrome 157 / desktop",
		ID:              &helloChrome157,
		SpecFactory:     chrome157ClientHelloSpec,
		UA:              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
		SecChUa:         `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`,
		SecChUaPlatform: `"Windows"`,
		SecChUaMobile:   "?0",
		AcceptLanguage:  "en-US,en;q=0.9",
		TCPKeepAlive:    chromeTCPKeepAlive,
	},
}

var mobileFingerprintProfiles = []FingerprintProfile{
	{
		Name:            "Chrome 157 / mobile",
		ID:              &helloChrome157,
		SpecFactory:     chrome157ClientHelloSpec,
		UA:              "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
		SecChUa:         `"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"`,
		SecChUaPlatform: `"Android"`,
		SecChUaMobile:   "?1",
		AcceptLanguage:  "en-US,en;q=0.9",
		TCPKeepAlive:    chromeTCPKeepAlive,
	},
}

func normalizeFingerprintMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "mobile", "desktop":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "auto"
	}
}

func fingerprintProfilesForMode(mode string) []FingerprintProfile {
	switch normalizeFingerprintMode(mode) {
	case "mobile":
		return mobileFingerprintProfiles
	case "desktop":
		return desktopFingerprintProfiles
	default:
		profiles := make([]FingerprintProfile, 0, len(desktopFingerprintProfiles)+len(mobileFingerprintProfiles))
		profiles = append(profiles, desktopFingerprintProfiles...)
		return append(profiles, mobileFingerprintProfiles...)
	}
}

// Fingerprinter manages TLS fingerprint selection and rotation.
type Fingerprinter struct {
	mu      sync.RWMutex
	current FingerprintProfile
}

// NewFingerprinter creates a new fingerprint manager.
func NewFingerprinter(mode ...string) *Fingerprinter {
	selectedMode := "auto"
	if len(mode) > 0 {
		selectedMode = mode[0]
	}
	profiles := fingerprintProfilesForMode(selectedMode)
	fp := &Fingerprinter{current: profiles[rand.Intn(len(profiles))]}
	return fp
}

// GetProfile returns the currently active fingerprint profile.
// The identity remains fixed for the connection lifetime. Rotating HTTP headers
// without rebuilding the underlying TLS/HTTP2 connection creates an internally
// inconsistent fingerprint that is easier to classify than a stable client.
func (f *Fingerprinter) GetProfile() FingerprintProfile {
	f.mu.RLock()
	defer f.mu.RUnlock()
	current := f.current
	return current
}

// GetCurrentName returns the current fingerprint name for display.
func (f *Fingerprinter) GetCurrentName() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.current.Name
}

// CreateTLSTransport creates an http.Transport with the specified uTLS fingerprint.
// If realityKey and shieldDomain are provided, REALITY protocol is used with a
// dedicated http2.Transport so we get full H/2 stream multiplexing even though
// the TLS layer is handled by uTLS (net/http cannot negotiate H/2 through a
// custom DialTLS returning a non-*tls.Conn).
func CreateTLSTransport(profile FingerprintProfile, serverAddr string, serverDialAddr string, realityPub, psk []byte, shieldDomain string, tlsCertSHA256 []byte, verifyServerCertificate bool) http.RoundTripper {
	if len(realityPub) > 0 {
		return createRealityHTTP2Transport(profile, serverDialAddr, realityPub, psk, shieldDomain, tlsCertSHA256, verifyServerCertificate)
	}

	// Standard (non-REALITY) path — use net/http transport with ForceAttemptHTTP2.
	tracker := newConnectionTracker()
	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := dialFirstReachable(dialCandidates(serverDialAddr, addr), func(dialAddr string, timeout time.Duration) (net.Conn, error) {
				return dialUTLS(dialAddr, timeout, profile, nil, nil, shieldDomain, tlsCertSHA256, verifyServerCertificate)
			})
			if err != nil {
				return nil, err
			}
			return tracker.track(conn), nil
		},
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   192,
		MaxConnsPerHost:       384,
		IdleConnTimeout:       120 * time.Second,
		ResponseHeaderTimeout: 22 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &trackedRoundTripper{base: transport, tracker: tracker}
}

// createRealityHTTP2Transport builds an http2.Transport whose DialTLSContext
// uses uTLS + REALITY marker embedding so we get:
//   - uTLS ClientHello that mimics a real browser (DPI bypass)
//   - REALITY visibility marker in the TLS SessionID
//   - True HTTP/2 multiplexing: up to 250 concurrent streams on ONE TCP connection
//
// This replaces the old forced-HTTP/1.1 path and should multiply throughput
// by the number of parallel push/poll workers (64 / 16 = 80 streams).
func createRealityHTTP2Transport(profile FingerprintProfile, serverDialAddr string, realityPub, psk []byte, shieldDomain string, tlsCertSHA256 []byte, verifyServerCertificate bool) http.RoundTripper {
	tracker := newConnectionTracker()
	// Chromium advertises a 6 MiB per-stream receive window and grows the
	// connection receive window to 15 MiB. ConfigureTransports is used only to
	// attach the public net/http HTTP2Config to x/net/http2; clearing ConnPool
	// makes the returned transport dial through uTLS below as before.
	configSource := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: (15 << 20) - 65535,
		MaxReceiveBufferPerStream:     6 << 20,
	}}
	t, err := http2.ConfigureTransports(configSource)
	if err != nil {
		// configSource is new and private to this call, so registration cannot
		// normally fail. Keep a safe fallback for forward compatibility.
		LogOperationalFailure("transport", "browser-like HTTP/2 flow configuration unavailable", err)
		t = &http2.Transport{}
	}
	t.ConnPool = nil
	t.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		conn, err := dialFirstReachable(dialCandidates(serverDialAddr, addr), func(dialAddr string, timeout time.Duration) (net.Conn, error) {
			return dialUTLS(dialAddr, timeout, profile, realityPub, psk, shieldDomain, tlsCertSHA256, verifyServerCertificate)
		})
		if err != nil {
			return nil, err
		}
		return tracker.track(conn), nil
	}
	// Chromium advertises a 64 KiB HPACK table and a 256 KiB header-list
	// limit and keeps the HTTP/2 default frame size (16 KiB) without
	// announcing it. x/net announces 1 MiB unless told otherwise; with the
	// default set here the record shaper drops the redundant entry, so the
	// opening SETTINGS carry Chromium's four entries.
	t.MaxReadFrameSize = 16 << 10
	t.MaxHeaderListSize = 256 << 10
	t.MaxDecoderHeaderTableSize = 64 << 10
	t.MaxEncoderHeaderTableSize = 64 << 10
	t.StrictMaxConcurrentStreams = false
	t.WriteByteTimeout = 15 * time.Second
	return &trackedRoundTripper{base: t, tracker: tracker}
}

// dialUTLS opens a TCP connection and performs a uTLS handshake.
// If realityKey is non-nil the REALITY visibility marker is embedded in the SessionID.
// nextProtos is always ["h2", "http/1.1"] unless overridden.
func dialUTLS(addr string, timeout time.Duration, profile FingerprintProfile, realityPub, psk []byte, shieldDomain string, tlsCertSHA256 []byte, verifyServerCertificate ...bool) (net.Conn, error) {
	dialer := profileDialer(profile)
	if timeout > 0 {
		dialer.Timeout = timeout
	}
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		// The handshake of a preferred endpoint is bounded too, so a path that
		// accepts TCP but stalls falls back to the next endpoint quickly.
		_ = tcpConn.SetDeadline(time.Now().Add(2 * timeout))
	}

	sni := normalizeServerName(shieldDomain)
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		if host == "" {
			host = addr
		}
		sni = normalizeServerName(host)
	}

	// Always negotiate h2 — this is what makes HTTP/2 mux work in REALITY mode.
	nextProtos := []string{"h2", "http/1.1"}

	verifyPublicIdentity := len(verifyServerCertificate) > 0 && verifyServerCertificate[0]
	cfg := &utls.Config{
		ServerName: sni,
		// REALITY authenticates via the per-connection marker embedded in the
		// SessionID + the PSK, NOT the TLS certificate: the server's self-signed
		// cert never matches the rotating shield SNI, so standard hostname
		// verification must be skipped in REALITY mode (as with an explicit cert
		// pin). Confidentiality comes from the outer TLS 1.3 record layer.
		InsecureSkipVerify: len(tlsCertSHA256) > 0 || (len(realityPub) > 0 && !verifyPublicIdentity),
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS12,
		// Chrome (BoringSSL) sends full-size records from the first byte; Go's
		// default starts a connection with small records and grows them.
		DynamicRecordSizingDisabled: true,
	}

	helloID := *profile.ID
	applyPreset := profile.SpecFactory != nil || len(realityPub) > 0
	if applyPreset {
		helloID = utls.HelloCustom
	}
	tlsConn := utls.UClient(tcpConn, cfg, helloID)

	if applyPreset {
		// Apply a fresh browser preset on both public-TLS and REALITY paths.
		// Failing closed avoids silently emitting Go's empty HelloCustom profile.
		spec, err := clientHelloSpecForProfile(profile)
		if err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("build browser ClientHello: %w", err)
		}
		for _, ext := range spec.Extensions {
			if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
				alpnExt.AlpnProtocols = []string{"h2", "http/1.1"}
			}
		}
		if err := tlsConn.ApplyPreset(&spec); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("apply browser ClientHello: %w", err)
		}
	}

	if len(realityPub) > 0 {
		// Embed a per-connection REALITY marker in the TLS SessionID field.
		// EmbedMarkerInSessionID writes the marker (HMAC over the server pubkey +
		// a fresh nonce) AND the crypto-random nonce, so the whole 32-byte
		// SessionID is unique every dial — no static prefix left to fingerprint.
		var sid [32]byte
		shared.EmbedMarkerInSessionID(sid[:], realityPub, psk)
		if tlsConn.HandshakeState.Hello != nil {
			tlsConn.HandshakeState.Hello.SessionId = sid[:]
		} else {
			LogRateLimitedEvent("reality", "client marker could not be embedded")
		}
	}

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	if len(tlsCertSHA256) > 0 {
		if err := verifyPeerCertificatePin(tlsConn.ConnectionState().PeerCertificates, tlsCertSHA256); err != nil {
			tcpConn.Close()
			return nil, err
		}
	}
	if timeout > 0 {
		_ = tcpConn.SetDeadline(time.Time{})
	}

	if len(realityPub) > 0 {
		// Record Shaping v2 sits above the established outer TLS session and
		// below HTTP/2. Legacy TLS remains on its established path.
		shaped := shared.NewRecordShapingConn(tlsConn, shared.RecordShapingOptions{
			SenderPacingMode:           shared.SenderPacingRecordOnly,
			ObserveHTTP2Flow:           true,
			CoalesceHTTP2WindowUpdates: true,
			BrowserRecords:             true,
		})
		LogState("transport", "external record shaping enabled")
		return shaped, nil
	}
	return tlsConn, nil
}
