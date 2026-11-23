package mobilelink

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type SecretLookup func(installationID string) ([]byte, bool)

type Relay struct {
	baseDomain  string
	secrets     SecretLookup
	mu          sync.RWMutex
	sessions    map[string]*controlSession
	pending     map[string]*pendingConnection
	staticHosts map[string]string
	replay      replayCache
}

type controlSession struct {
	conn   net.Conn
	secret []byte
	mu     sync.Mutex
}

type pendingConnection struct {
	installationID string
	data           chan net.Conn
}

func NewRelay(baseDomain string, secrets SecretLookup) (*Relay, error) {
	baseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	if baseDomain == "" || secrets == nil {
		return nil, errors.New("mobile link relay requires a base domain and secret lookup")
	}
	return &Relay{
		baseDomain:  baseDomain,
		secrets:     secrets,
		sessions:    make(map[string]*controlSession),
		pending:     make(map[string]*pendingConnection),
		staticHosts: make(map[string]string),
	}, nil
}

// AddStaticHostname maps one exact public hostname to an installation. It is
// intended for single-installation DuckDNS deployments that cannot provide a
// wildcard record. Exact matching prevents suffix or subdomain confusion.
func (relay *Relay) AddStaticHostname(hostname, installationID string) error {
	hostname = strings.Trim(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" || strings.ContainsAny(hostname, "/\\:\x00") {
		return errors.New("invalid static Mobile Link hostname")
	}
	if len(installationID) != 32 {
		return errors.New("invalid static Mobile Link installation id")
	}
	if _, err := hex.DecodeString(installationID); err != nil {
		return errors.New("invalid static Mobile Link installation id")
	}
	if secret, ok := relay.secrets(installationID); !ok || InstallationID(secret) != installationID {
		return errors.New("static Mobile Link hostname references an unknown installation")
	}
	relay.mu.Lock()
	relay.staticHosts[hostname] = installationID
	relay.mu.Unlock()
	return nil
}

func (relay *Relay) ServeAgents(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go relay.handleAgentConnection(conn)
	}
}

func (relay *Relay) ServeMobile(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go relay.handleMobileConnection(conn)
	}
}

func (relay *Relay) handleAgentConnection(conn net.Conn) {
	owned := false
	defer func() {
		if !owned {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	message, err := ReadMessage(conn)
	if err != nil {
		return
	}
	secret, ok := relay.secrets(message.InstallationID)
	now := time.Now()
	if !ok || InstallationID(secret) != message.InstallationID || Verify(secret, message, now) != nil || !relay.replay.accept(message.InstallationID, message.Nonce, now) {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	switch message.Type {
	case "register":
		owned = true
		relay.runControl(message.InstallationID, secret, conn)
	case "data":
		owned = relay.attachData(message, secret, conn)
	}
}

func (relay *Relay) runControl(installationID string, secret []byte, conn net.Conn) {
	session := &controlSession{conn: conn, secret: append([]byte(nil), secret...)}
	relay.mu.Lock()
	previous := relay.sessions[installationID]
	relay.sessions[installationID] = session
	relay.mu.Unlock()
	if previous != nil {
		_ = previous.conn.Close()
	}
	defer func() {
		relay.mu.Lock()
		if relay.sessions[installationID] == session {
			delete(relay.sessions, installationID)
		}
		relay.mu.Unlock()
		_ = conn.Close()
	}()
	for {
		message, err := ReadMessage(conn)
		if err != nil {
			return
		}
		now := time.Now()
		if message.InstallationID != installationID || Verify(secret, message, now) != nil || !relay.replay.accept(installationID, message.Nonce, now) {
			return
		}
		if message.Type == "ping" {
			_ = session.send(Message{Type: "pong", InstallationID: installationID})
		}
	}
}

func (relay *Relay) attachData(message Message, secret []byte, conn net.Conn) bool {
	relay.mu.Lock()
	pending := relay.pending[message.ConnectionID]
	if pending != nil && pending.installationID == message.InstallationID {
		delete(relay.pending, message.ConnectionID)
	}
	relay.mu.Unlock()
	if pending == nil || pending.installationID != message.InstallationID {
		return false
	}
	ready := Message{Type: "ready", InstallationID: message.InstallationID, ConnectionID: message.ConnectionID}
	if err := Sign(secret, &ready, time.Now()); err != nil || WriteMessage(conn, ready) != nil {
		return false
	}
	select {
	case pending.data <- conn:
		return true
	default:
		return false
	}
}

func (relay *Relay) handleMobileConnection(conn net.Conn) {
	serverName, preface, err := ReadClientHelloSNI(conn, 10*time.Second)
	if err != nil {
		_ = conn.Close()
		return
	}
	installationID, err := relay.installationFromServerName(serverName)
	if err != nil {
		_ = conn.Close()
		return
	}
	relay.mu.RLock()
	session := relay.sessions[installationID]
	relay.mu.RUnlock()
	if session == nil {
		_ = conn.Close()
		return
	}
	connectionID, err := randomID()
	if err != nil {
		_ = conn.Close()
		return
	}
	pending := &pendingConnection{installationID: installationID, data: make(chan net.Conn, 1)}
	relay.mu.Lock()
	relay.pending[connectionID] = pending
	relay.mu.Unlock()
	defer func() {
		relay.mu.Lock()
		delete(relay.pending, connectionID)
		relay.mu.Unlock()
	}()
	if err := session.send(Message{Type: "open", InstallationID: installationID, ConnectionID: connectionID}); err != nil {
		_ = conn.Close()
		return
	}
	select {
	case dataConn := <-pending.data:
		if _, err := dataConn.Write(preface); err != nil {
			_ = dataConn.Close()
			_ = conn.Close()
			return
		}
		bridge(conn, dataConn)
	case <-time.After(15 * time.Second):
		_ = conn.Close()
	}
}

func (relay *Relay) installationFromServerName(serverName string) (string, error) {
	relay.mu.RLock()
	staticID := relay.staticHosts[serverName]
	relay.mu.RUnlock()
	if staticID != "" {
		return staticID, nil
	}
	suffix := "." + relay.baseDomain
	if !strings.HasSuffix(serverName, suffix) {
		return "", errors.New("mobile link SNI is outside the configured domain")
	}
	id := strings.TrimSuffix(serverName, suffix)
	if strings.Contains(id, ".") || len(id) != 32 {
		return "", errors.New("invalid mobile link installation hostname")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("invalid mobile link installation hostname")
	}
	if _, ok := relay.secrets(id); !ok {
		return "", errors.New("unknown mobile link installation")
	}
	return id, nil
}

func (session *controlSession) send(message Message) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := Sign(session.secret, &message, time.Now()); err != nil {
		return err
	}
	if err := session.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	defer session.conn.SetWriteDeadline(time.Time{})
	return WriteMessage(session.conn, message)
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate mobile link connection id: %w", err)
	}
	return hex.EncodeToString(value), nil
}
