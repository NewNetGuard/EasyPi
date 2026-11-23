package main

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"chameleon/shared"
)

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.Trim(host, "[]"))
}

const (
	authTimestampTolerance = 120
	nonceStoreMaxEntries   = 200000
)

type contextKey int

const (
	contextKeyClientID contextKey = iota
	contextKeyCryptoSession
)

type replayNonceStore struct {
	mu          sync.Mutex
	seen        map[string]int64
	lastCleanup int64
}

func newReplayNonceStore() replayNonceStore {
	return replayNonceStore{seen: make(map[string]int64)}
}

func (s *replayNonceStore) register(nonce string, expiresAt, now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if now-s.lastCleanup >= authTimestampTolerance {
		for value, expiry := range s.seen {
			if expiry < now {
				delete(s.seen, value)
			}
		}
		s.lastCleanup = now
	}
	if _, exists := s.seen[nonce]; exists {
		return false
	}
	if len(s.seen) >= nonceStoreMaxEntries {
		return false
	}
	s.seen[nonce] = expiresAt
	return true
}

// sessionAuthMiddleware accepts only requests authenticated by an active
// negotiated session. There is deliberately no PSK-only compatibility path.
func sessionAuthMiddleware(headerName string, sessions *cryptoSessionManager, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get(headerName)
		token := strings.TrimPrefix(auth, "Bearer ")
		if auth == "" || token == auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(token, ":", 5)
		if len(parts) != 5 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		clientHMACHex, timestampText, nonce, clientID, sessionID := parts[0], parts[1], parts[2], parts[3], parts[4]
		if !sessions.knownClient(clientID) {
			logRateLimitedEvent("auth", "rejected caller-selected client identity")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		nonceBytes, nonceErr := hex.DecodeString(nonce)
		sessionBytes, sessionErr := hex.DecodeString(sessionID)
		if nonceErr != nil || len(nonceBytes) != 16 || sessionErr != nil || len(sessionBytes) != 32 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		timestamp, err := strconv.ParseInt(timestampText, 10, 64)
		now := time.Now().Unix()
		if err != nil || timestamp < now-authTimestampTolerance || timestamp > now+authTimestampTolerance {
			logRateLimitedEvent("auth", "rejected stale timestamp")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session := sessions.get(sessionID, clientID)
		if session == nil {
			logRateLimitedEvent("auth", "rejected unknown or expired session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		clientMAC, err := hex.DecodeString(clientHMACHex)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		expected := shared.ComputeSessionRequestMAC(
			session.authKey,
			timestampText,
			nonce,
			clientID,
			sessionID,
			r.Method,
			requestPath(r),
		)
		if !hmac.Equal(clientMAC, expected) {
			logRateLimitedEvent("auth", "rejected invalid session authenticator")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !session.nonces.register(nonce, timestamp+authTimestampTolerance, now) {
			logRateLimitedEvent("auth", "rejected replayed session authenticator")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !sessions.isActive(session) || session.ctx == nil || session.ctx.Err() != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		session.touch()
		ctx, cancel := context.WithCancel(r.Context())
		stopRevocation := context.AfterFunc(session.ctx, cancel)
		stopBody := context.AfterFunc(ctx, func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		})
		defer func() {
			stopBody()
			stopRevocation()
			cancel()
		}()
		ctx = context.WithValue(ctx, contextKeyClientID, clientID)
		ctx = context.WithValue(ctx, contextKeyCryptoSession, session)
		next(w, r.WithContext(ctx))
	}
}

func requestPath(r *http.Request) string {
	path := r.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func SessionAuthMiddleware(sessions *cryptoSessionManager, next http.HandlerFunc) http.HandlerFunc {
	return sessionAuthMiddleware("Authorization", sessions, next)
}

func ConnectSessionAuthMiddleware(sessions *cryptoSessionManager, next http.HandlerFunc) http.HandlerFunc {
	return sessionAuthMiddleware("Proxy-Authorization", sessions, next)
}

func ClientIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKeyClientID).(string)
	return value
}

func CryptoSessionFromContext(ctx context.Context) *cryptoSession {
	value, _ := ctx.Value(contextKeyCryptoSession).(*cryptoSession)
	return value
}

func CipherFromContext(ctx context.Context) *Cipher {
	session := CryptoSessionFromContext(ctx)
	if session == nil {
		return nil
	}
	return session.cipher
}

func GenerateSessionAuthHeader(
	authKey []byte,
	sessionID, nonce, clientID, method, path string,
) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := shared.ComputeSessionRequestMAC(authKey, timestamp, nonce, clientID, sessionID, method, path)
	return fmt.Sprintf("Bearer %s:%s:%s:%s:%s", hex.EncodeToString(mac), timestamp, nonce, clientID, sessionID)
}
