//go:build quicdatagram
// +build quicdatagram

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"chameleon/shared"

	"github.com/quic-go/quic-go"
)

type quicDatagramAuthPayload struct {
	Timestamp int64  `json:"ts"`
	Nonce     string `json:"nonce"`
	ClientID  string `json:"client_id"`
	HMAC      string `json:"hmac"`
}

func verifyQUICDatagramAuth(psk []byte, payload []byte) (string, error) {
	var auth quicDatagramAuthPayload
	if err := json.Unmarshal(payload, &auth); err != nil {
		return "", fmt.Errorf("bad auth payload: %w", err)
	}
	if auth.ClientID == "" {
		return "", fmt.Errorf("empty client id")
	}
	if !hmac.Equal([]byte(auth.ClientID), []byte(shared.ClientIDForPSK(psk))) {
		return "", fmt.Errorf("caller-selected client id")
	}
	if _, err := hex.DecodeString(auth.Nonce); err != nil || len(auth.Nonce) != 32 {
		return "", fmt.Errorf("bad nonce")
	}

	now := time.Now().Unix()
	if drift := now - auth.Timestamp; drift > authTimestampTolerance || drift < -authTimestampTolerance {
		return "", fmt.Errorf("stale auth timestamp")
	}

	ts := strconv.FormatInt(auth.Timestamp, 10)
	message := fmt.Sprintf("%s:%s:%s", ts, auth.Nonce, auth.ClientID)
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(message))
	expected := mac.Sum(nil)

	provided, err := hex.DecodeString(auth.HMAC)
	if err != nil {
		return "", fmt.Errorf("bad hmac encoding")
	}
	if !hmac.Equal(provided, expected) {
		return "", fmt.Errorf("hmac mismatch")
	}
	if !registerNonce(auth.ClientID, auth.Nonce, now) {
		return "", fmt.Errorf("replay detected")
	}
	return auth.ClientID, nil
}

func startQUICDatagramServer(cfg *ServerConfig, psk []byte, demasker *Demasker, cipher *Cipher) (*quic.Listener, error) {
	if cfg.QUICDatagramPort <= 0 {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load tls cert for datagram listener failed: %w", err)
	}

	addr := fmt.Sprintf(":%d", cfg.QUICDatagramPort)
	listener, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{shared.QUICDatagramALPN},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 12 * time.Second,
		MaxIdleTimeout:  90 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("listen quic datagram failed: %w", err)
	}

	logState("quic-dgram", "listener started")
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go handleQUICDatagramConn(conn, psk, demasker, cipher)
		}
	}()

	return listener, nil
}

func handleQUICDatagramConn(conn *quic.Conn, psk []byte, demasker *Demasker, cipher *Cipher) {
	var (
		authed               bool
		clientID             string
		session              *clientSession
		sendDone             = make(chan struct{})
		senderRun            bool
		finishSessionRequest func()
	)
	defer func() {
		close(sendDone)
		if finishSessionRequest != nil {
			finishSessionRequest()
		}
	}()

	startSender := func() {
		if senderRun || session == nil {
			return
		}
		senderRun = true
		go func(s *clientSession) {
			for {
				select {
				case <-sendDone:
					return
				case <-conn.Context().Done():
					return
				case payload := <-s.outbox:
					if len(payload) == 0 {
						continue
					}
					padded := serverPadPacketBinary(payload)
					encrypted, err := cipher.Encrypt(padded)
					if err != nil {
						continue
					}
					frame, err := shared.EncodeDatagramFrame(shared.DatagramFrameTypeData, encrypted)
					if err != nil {
						continue
					}
					if err := conn.SendDatagram(frame); err != nil {
						return
					}
				}
			}
		}(session)
	}

	for {
		raw, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}

		frameType, payload, err := shared.DecodeDatagramFrame(raw)
		if err != nil {
			continue
		}

		switch frameType {
		case shared.DatagramFrameTypeAuth:
			cid, err := verifyQUICDatagramAuth(psk, payload)
			if err != nil {
				logRateLimitedEvent("quic-dgram", "authentication rejected")
				_ = conn.CloseWithError(0x201, "auth failed")
				return
			}
			clientID = cid
			session = getSession(clientID, remoteHost(conn.RemoteAddr().String()))
			if session == nil {
				_ = conn.CloseWithError(0x202, "server at capacity")
				return
			}
			var admitted bool
			finishSessionRequest, admitted = session.tryBeginRequest()
			if !admitted {
				_ = conn.CloseWithError(0x203, "client connection limit reached")
				return
			}
			authed = true
			startSender()

		case shared.DatagramFrameTypeData:
			if !authed || session == nil || clientID == "" {
				continue
			}
			if err := processIncomingPayload(payload, session, demasker, cipher); err != nil {
				logOperationalFailure("quic-dgram", "tunnel payload rejected", err)
			}

		case shared.DatagramFrameTypePing:
			if !authed {
				continue
			}
			// Keepalive only.

		default:
			continue
		}
	}
}
