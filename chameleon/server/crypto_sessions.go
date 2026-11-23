package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/shared"
)

const (
	sessionChallengeTTL  = 30 * time.Second
	cryptoSessionIdleTTL = 24 * time.Hour
	maxSessionChallenges = 4096
)

type sessionChallenge struct {
	value     string
	expiresAt time.Time
}

type cryptoSession struct {
	id             string
	clientID       string
	clientInstance string
	authKey        []byte
	streamKey      []byte
	cipher         *Cipher
	nonces         replayNonceStore
	lastSeen       atomic.Int64
	ctx            context.Context
	cancel         context.CancelFunc
	allowedIP      net.IP
	packetPSK      []byte
}

func (s *cryptoSession) runtimeID() string {
	if s == nil {
		return ""
	}
	return s.clientID + ":" + s.clientInstance
}

func (s *cryptoSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

type cryptoSessionManager struct {
	psk              []byte
	clientID         string
	credentialsFile  string
	credentials      map[string]clientCredential
	credentialDigest [32]byte
	credentialMu     sync.Mutex
	credentialNet    *net.IPNet
	legacyAddress    net.IP

	mu             sync.Mutex
	challenges     map[string]sessionChallenge
	sessions       map[string]*cryptoSession
	activeByClient map[string]string // keyed by authenticated client + process instance
}

func (m *cryptoSessionManager) setCredentialNetwork(cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil || network == nil {
		return fmt.Errorf("invalid credential network")
	}
	legacy := append(net.IP(nil), network.IP.To4()...)
	legacy[3] += 2
	m.credentialNet = network
	m.legacyAddress = legacy
	return nil
}

type sessionChallengeResponse struct {
	Protocol    string `json:"protocol"`
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	// Padding randomises the body size; see session_shape.go.
	Padding string `json:"pad,omitempty"`
}

type sessionEstablishRequest struct {
	Protocol       string `json:"protocol"`
	ChallengeID    string `json:"challenge_id"`
	ClientID       string `json:"client_id"`
	ClientInstance string `json:"client_instance"`
	ClientNonce    string `json:"client_nonce"`
}

type sessionEstablishResponse struct {
	Protocol    string `json:"protocol"`
	InnerAEAD   string `json:"inner_aead"`
	SessionID   string `json:"session_id"`
	ServerNonce string `json:"server_nonce"`
	ServerProof string `json:"server_proof"`
	// Padding randomises the body size; see session_shape.go.
	Padding string `json:"pad,omitempty"`
}

func newCryptoSessionManager(psk []byte) *cryptoSessionManager {
	manager := &cryptoSessionManager{
		psk:            append([]byte(nil), psk...),
		clientID:       shared.ClientIDForPSK(psk),
		challenges:     make(map[string]sessionChallenge),
		sessions:       make(map[string]*cryptoSession),
		activeByClient: make(map[string]string),
	}
	_ = manager.setCredentialNetwork("10.10.0.1/24")
	return manager
}

func secureHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (m *cryptoSessionManager) challenge(now time.Time) (sessionChallengeResponse, error) {
	id, err := secureHex(16)
	if err != nil {
		return sessionChallengeResponse{}, fmt.Errorf("generate challenge id: %w", err)
	}
	value, err := secureHex(32)
	if err != nil {
		return sessionChallengeResponse{}, fmt.Errorf("generate challenge: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	if len(m.challenges) >= maxSessionChallenges {
		return sessionChallengeResponse{}, fmt.Errorf("challenge capacity reached")
	}
	m.challenges[id] = sessionChallenge{value: value, expiresAt: now.Add(sessionChallengeTTL)}
	return sessionChallengeResponse{Protocol: shared.SessionProtocolID, ChallengeID: id, Challenge: value}, nil
}

func (m *cryptoSessionManager) establish(
	req sessionEstablishRequest,
	bootstrapMAC []byte,
	now time.Time,
) (sessionEstablishResponse, *cryptoSession, error) {
	_ = m.refreshCredentials()
	m.mu.Lock()
	credential, known := m.credentials[req.ClientID]
	if m.credentialsFile == "" && req.ClientID == m.clientID {
		credential = clientCredential{psk: m.psk}
		known = true
	}
	m.mu.Unlock()
	if req.Protocol != shared.SessionProtocolID || !known {
		return sessionEstablishResponse{}, nil, fmt.Errorf("incompatible session request")
	}
	instanceBytes, instanceErr := hex.DecodeString(req.ClientInstance)
	clientNonce, nonceErr := hex.DecodeString(req.ClientNonce)
	challengeID, challengeIDErr := hex.DecodeString(req.ChallengeID)
	if instanceErr != nil || len(instanceBytes) != 16 || nonceErr != nil || len(clientNonce) != 32 ||
		challengeIDErr != nil || len(challengeID) != 16 {
		return sessionEstablishResponse{}, nil, fmt.Errorf("invalid session request")
	}

	m.mu.Lock()
	m.cleanupLocked(now)
	challenge, ok := m.challenges[req.ChallengeID]
	if !ok || now.After(challenge.expiresAt) {
		m.mu.Unlock()
		return sessionEstablishResponse{}, nil, fmt.Errorf("unknown or expired challenge")
	}
	expected := shared.ComputeBootstrapMAC(
		credential.psk,
		req.ChallengeID,
		challenge.value,
		req.ClientID,
		req.ClientInstance,
		req.ClientNonce,
	)
	if !hmac.Equal(bootstrapMAC, expected) {
		m.mu.Unlock()
		return sessionEstablishResponse{}, nil, fmt.Errorf("invalid bootstrap authenticator")
	}
	// Consume atomically. Concurrent copies cannot create two sessions.
	delete(m.challenges, req.ChallengeID)
	m.mu.Unlock()

	sessionID, err := secureHex(32)
	if err != nil {
		return sessionEstablishResponse{}, nil, fmt.Errorf("generate session id: %w", err)
	}
	serverNonceHex, err := secureHex(32)
	if err != nil {
		return sessionEstablishResponse{}, nil, fmt.Errorf("generate server nonce: %w", err)
	}
	serverNonce, _ := hex.DecodeString(serverNonceHex)
	keys, err := shared.DeriveSessionKeys(
		credential.psk,
		clientNonce,
		serverNonce,
		sessionID,
		req.ClientID,
		req.ClientInstance,
	)
	if err != nil {
		return sessionEstablishResponse{}, nil, err
	}
	cipher, err := NewCipher(keys, sessionID)
	if err != nil {
		return sessionEstablishResponse{}, nil, err
	}
	sessionContext, cancelSession := context.WithCancel(context.Background())
	session := &cryptoSession{
		id:             sessionID,
		clientID:       req.ClientID,
		clientInstance: req.ClientInstance,
		authKey:        append([]byte(nil), keys.AuthKey...),
		streamKey:      append([]byte(nil), keys.StreamKey...),
		cipher:         cipher,
		nonces:         newReplayNonceStore(),
		ctx:            sessionContext,
		cancel:         cancelSession,
		allowedIP:      credential.address,
		packetPSK:      append([]byte(nil), credential.psk...),
	}
	session.touch()

	m.mu.Lock()
	// A revocation that raced key derivation must win publication.
	if m.credentialsFile != "" {
		current, exists := m.credentials[req.ClientID]
		if !exists || !hmac.Equal(current.psk, credential.psk) || !current.address.Equal(credential.address) {
			m.mu.Unlock()
			cancelSession()
			return sessionEstablishResponse{}, nil, fmt.Errorf("credential revoked")
		}
	}
	runtimeID := session.runtimeID()
	var oldRuntimes []string
	// A credential names one device, not unlimited caller-chosen instances.
	// Reconnect replaces its previous process and releases its resource budget.
	for oldID, old := range m.sessions {
		if old.clientID == session.clientID {
			old.cancel()
			delete(m.sessions, oldID)
			delete(m.activeByClient, old.runtimeID())
			oldRuntimes = append(oldRuntimes, old.runtimeID())
		}
	}
	m.sessions[sessionID] = session
	m.activeByClient[runtimeID] = sessionID
	m.mu.Unlock()
	for _, old := range oldRuntimes {
		revokeClientRuntime(old)
	}
	revokeClientRuntime(runtimeID)

	proof := shared.ComputeServerProof(
		keys.AuthKey,
		sessionID,
		req.ClientNonce,
		serverNonceHex,
		req.ClientID,
		req.ClientInstance,
	)
	return sessionEstablishResponse{
		Protocol:    shared.SessionProtocolID,
		InnerAEAD:   shared.InnerProtocolID,
		SessionID:   sessionID,
		ServerNonce: serverNonceHex,
		ServerProof: hex.EncodeToString(proof),
	}, session, nil
}

func (m *cryptoSessionManager) get(sessionID, clientID string) *cryptoSession {
	_ = m.refreshCredentials()
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	session := m.sessions[sessionID]
	if session == nil || session.clientID != clientID || m.activeByClient[session.runtimeID()] != sessionID {
		return nil
	}
	return session
}

func (m *cryptoSessionManager) isActive(session *cryptoSession) bool {
	_ = m.refreshCredentials()
	if session == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[session.id] == session && m.activeByClient[session.runtimeID()] == session.id
}

func (m *cryptoSessionManager) cleanupLocked(now time.Time) {
	for id, challenge := range m.challenges {
		if now.After(challenge.expiresAt) {
			delete(m.challenges, id)
		}
	}
	for id, session := range m.sessions {
		lastSeen := time.Unix(0, session.lastSeen.Load())
		if now.Sub(lastSeen) > cryptoSessionIdleTTL {
			if session.cancel != nil {
				session.cancel()
			}
			delete(m.sessions, id)
			if m.activeByClient[session.runtimeID()] == id {
				delete(m.activeByClient, session.runtimeID())
			}
		}
	}
}
