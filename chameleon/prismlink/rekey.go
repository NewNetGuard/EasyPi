package prismlink

import (
	"errors"
	"sync"
	"time"
)

// IsServerHello reports whether a datagram is a server handshake response. It
// does not authenticate the packet.
func IsServerHello(packet []byte) bool {
	header, err := decodeHeader(packet)
	return err == nil && header.typ == PacketServerHello
}

// SessionPair lets an endpoint switch to new keys without a gap: packets
// sealed with the previous session are still accepted for a grace period.
type SessionPair struct {
	mu            sync.Mutex
	current       *Session
	previous      *Session
	previousUntil time.Time
}

func NewSessionPair(current *Session) *SessionPair {
	return &SessionPair{current: current}
}

func (pair *SessionPair) Current() *Session {
	pair.mu.Lock()
	defer pair.mu.Unlock()
	return pair.current
}

// Promote makes next the sending session and keeps the replaced one for
// receiving until grace expires.
func (pair *SessionPair) Promote(next *Session, now time.Time, grace time.Duration) {
	pair.mu.Lock()
	defer pair.mu.Unlock()
	pair.previous = pair.current
	pair.previousUntil = now.Add(grace)
	pair.current = next
}

// Open authenticates a packet with the session named in its header.
func (pair *SessionPair) Open(packet []byte, now time.Time) (PacketType, []byte, error) {
	id, ok := SessionID(packet)
	if !ok {
		return 0, nil, errors.New("invalid PrismLink session packet")
	}
	pair.mu.Lock()
	session := pair.current
	if session == nil || session.ID() != id {
		session = nil
		if pair.previous != nil && pair.previous.ID() == id && now.Before(pair.previousUntil) {
			session = pair.previous
		}
	}
	pair.mu.Unlock()
	if session == nil {
		return 0, nil, errors.New("unknown PrismLink session")
	}
	return session.Open(packet)
}
