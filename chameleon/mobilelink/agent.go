package mobilelink

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

type Agent struct {
	RelayAddress   string
	LocalAddress   string
	InstallationID string
	Secret         []byte
	TLSConfig      *tls.Config
	replay         replayCache
	workers        sync.WaitGroup
}

func (agent *Agent) Run(ctx context.Context) error {
	if agent.RelayAddress == "" || !isLoopbackTarget(agent.LocalAddress) || len(agent.Secret) != 32 || agent.InstallationID != InstallationID(agent.Secret) {
		return errors.New("invalid mobile link agent configuration")
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			agent.workers.Wait()
			return ctx.Err()
		}
		err := agent.runSession(ctx)
		if ctx.Err() != nil {
			agent.workers.Wait()
			return ctx.Err()
		}
		_ = err
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			agent.workers.Wait()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (agent *Agent) runSession(ctx context.Context) error {
	conn, err := agent.dialRelay()
	if err != nil {
		return err
	}
	defer conn.Close()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closed:
		}
	}()
	register := Message{Type: "register", InstallationID: agent.InstallationID}
	if err := Sign(agent.Secret, &register, time.Now()); err != nil {
		return err
	}
	if err := WriteMessage(conn, register); err != nil {
		return err
	}
	heartbeatDone := make(chan struct{})
	defer close(heartbeatDone)
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				ping := Message{Type: "ping", InstallationID: agent.InstallationID}
				if Sign(agent.Secret, &ping, time.Now()) != nil || conn.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil || WriteMessage(conn, ping) != nil {
					_ = conn.Close()
					return
				}
				_ = conn.SetWriteDeadline(time.Time{})
			}
		}
	}()
	for {
		message, err := ReadMessage(conn)
		if err != nil {
			return err
		}
		now := time.Now()
		if message.InstallationID != agent.InstallationID || Verify(agent.Secret, message, now) != nil || !agent.replay.accept(agent.InstallationID, message.Nonce, now) {
			return errors.New("relay sent an invalid mobile link control message")
		}
		if message.Type == "open" {
			agent.workers.Add(1)
			go func(connectionID string) {
				defer agent.workers.Done()
				agent.openData(ctx, connectionID)
			}(message.ConnectionID)
		}
	}
}

func isLoopbackTarget(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (agent *Agent) openData(ctx context.Context, connectionID string) {
	relayConn, err := agent.dialRelay()
	if err != nil {
		return
	}
	defer relayConn.Close()
	message := Message{Type: "data", InstallationID: agent.InstallationID, ConnectionID: connectionID}
	if Sign(agent.Secret, &message, time.Now()) != nil || WriteMessage(relayConn, message) != nil {
		return
	}
	ready, err := ReadMessage(relayConn)
	if err != nil || ready.Type != "ready" || ready.ConnectionID != connectionID || Verify(agent.Secret, ready, time.Now()) != nil || !agent.replay.accept(agent.InstallationID, ready.Nonce, time.Now()) {
		return
	}
	localDialer := net.Dialer{Timeout: 10 * time.Second}
	localConn, err := localDialer.DialContext(ctx, "tcp", agent.LocalAddress)
	if err != nil {
		return
	}
	bridge(relayConn, localConn)
}

func (agent *Agent) dialRelay() (net.Conn, error) {
	config := agent.TLSConfig
	if config == nil {
		config = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		config = config.Clone()
		if config.MinVersion < tls.VersionTLS13 {
			config.MinVersion = tls.VersionTLS13
		}
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", agent.RelayAddress, config)
}
