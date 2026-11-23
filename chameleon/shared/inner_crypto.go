package shared

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	InnerProtocolID      = "xchacha20poly1305-v4"
	innerCounterSize     = 8
	innerNoncePrefixSize = chacha20poly1305.NonceSizeX - innerCounterSize
	// InnerReplayWindow is the largest authenticated counter window that may
	// be processed out of order before ordered delivery resumes.
	InnerReplayWindow = 128
	innerReplayWindow = InnerReplayWindow
)

var (
	ErrInnerPacketTooSmall = errors.New("inner packet too small")
	ErrInnerReplay         = errors.New("inner packet replay detected")
	ErrInnerCounterExhaust = errors.New("inner packet counter exhausted")
)

// InnerCipher provides end-to-end authenticated encryption inside the outer
// TLS transport. Keys and nonce prefixes are unique to one negotiated session
// and one direction. A monotonically increasing counter is authenticated and
// checked with a bounded sliding window.
type InnerCipher struct {
	send cipherAEAD
	recv cipherAEAD

	sendPrefix [innerNoncePrefixSize]byte
	recvPrefix [innerNoncePrefixSize]byte
	sendAAD    []byte
	recvAAD    []byte
	sendNext   atomic.Uint64
	replay     counterWindow
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

type counterWindow struct {
	mu      sync.Mutex
	highest uint64
	bits    [2]uint64
}

// NewInnerCipher constructs a session-scoped XChaCha20-Poly1305 cipher.
func NewInnerCipher(
	sendKey, recvKey, sendNoncePrefix, recvNoncePrefix []byte,
	sessionID, sendDirection, recvDirection string,
) (*InnerCipher, error) {
	if len(sendKey) != chacha20poly1305.KeySize || len(recvKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("inner keys must contain %d bytes", chacha20poly1305.KeySize)
	}
	if len(sendNoncePrefix) != innerNoncePrefixSize || len(recvNoncePrefix) != innerNoncePrefixSize {
		return nil, fmt.Errorf("inner nonce prefixes must contain %d bytes", innerNoncePrefixSize)
	}
	if sessionID == "" || sendDirection == "" || recvDirection == "" || sendDirection == recvDirection {
		return nil, fmt.Errorf("invalid inner cipher session or directions")
	}

	send, err := chacha20poly1305.NewX(sendKey)
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}
	recv, err := chacha20poly1305.NewX(recvKey)
	if err != nil {
		return nil, fmt.Errorf("create receive cipher: %w", err)
	}

	cipher := &InnerCipher{
		send:    send,
		recv:    recv,
		sendAAD: []byte(InnerProtocolID + "\x00" + sessionID + "\x00" + sendDirection),
		recvAAD: []byte(InnerProtocolID + "\x00" + sessionID + "\x00" + recvDirection),
	}
	copy(cipher.sendPrefix[:], sendNoncePrefix)
	copy(cipher.recvPrefix[:], recvNoncePrefix)
	return cipher, nil
}

func innerNonce(prefix [innerNoncePrefixSize]byte, counter uint64) [chacha20poly1305.NonceSizeX]byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:innerNoncePrefixSize], prefix[:])
	binary.BigEndian.PutUint64(nonce[innerNoncePrefixSize:], counter)
	return nonce
}

func innerAAD(base []byte, counterBytes []byte) []byte {
	aad := make([]byte, 0, len(base)+1+innerCounterSize)
	aad = append(aad, base...)
	aad = append(aad, 0)
	aad = append(aad, counterBytes...)
	return aad
}

// Encrypt returns counter || ciphertext || authentication tag. The counter is
// never reused within a session, and the nonce prefix is derived by HKDF.
func (c *InnerCipher) Encrypt(plaintext []byte) ([]byte, error) {
	var counter uint64
	for {
		current := c.sendNext.Load()
		if current == ^uint64(0) {
			return nil, ErrInnerCounterExhaust
		}
		counter = current + 1
		if c.sendNext.CompareAndSwap(current, counter) {
			break
		}
	}
	var counterBytes [innerCounterSize]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	nonce := innerNonce(c.sendPrefix, counter)

	out := make([]byte, innerCounterSize, innerCounterSize+len(plaintext)+c.send.Overhead())
	copy(out, counterBytes[:])
	out = c.send.Seal(out, nonce[:], plaintext, innerAAD(c.sendAAD, counterBytes[:]))
	return out, nil
}

// Decrypt authenticates a packet and registers its counter atomically. A
// duplicate can be decrypted concurrently, but only one caller can commit it.
func (c *InnerCipher) Decrypt(packet []byte) ([]byte, error) {
	if len(packet) < innerCounterSize+c.recv.Overhead() {
		return nil, ErrInnerPacketTooSmall
	}
	counter := binary.BigEndian.Uint64(packet[:innerCounterSize])
	if counter == 0 || !c.replay.mayAccept(counter) {
		return nil, ErrInnerReplay
	}

	nonce := innerNonce(c.recvPrefix, counter)
	plaintext, err := c.recv.Open(
		nil,
		nonce[:],
		packet[innerCounterSize:],
		innerAAD(c.recvAAD, packet[:innerCounterSize]),
	)
	if err != nil {
		return nil, fmt.Errorf("authenticate inner packet: %w", err)
	}
	if !c.replay.register(counter) {
		return nil, ErrInnerReplay
	}
	return plaintext, nil
}

func (w *counterWindow) mayAccept(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mayAcceptLocked(counter)
}

func (w *counterWindow) mayAcceptLocked(counter uint64) bool {
	if counter == 0 {
		return false
	}
	if w.highest == 0 || counter > w.highest {
		return true
	}
	delta := w.highest - counter
	if delta >= innerReplayWindow {
		return false
	}
	if delta < 64 {
		return w.bits[0]&(uint64(1)<<delta) == 0
	}
	return w.bits[1]&(uint64(1)<<(delta-64)) == 0
}

func (w *counterWindow) register(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.mayAcceptLocked(counter) {
		return false
	}
	if w.highest == 0 {
		w.highest = counter
		w.bits[0] = 1
		return true
	}
	if counter > w.highest {
		shift := counter - w.highest
		switch {
		case shift >= innerReplayWindow:
			w.bits = [2]uint64{}
		case shift >= 64:
			w.bits[1] = w.bits[0] << (shift - 64)
			w.bits[0] = 0
		default:
			w.bits[1] = (w.bits[1] << shift) | (w.bits[0] >> (64 - shift))
			w.bits[0] <<= shift
		}
		w.highest = counter
		w.bits[0] |= 1
		return true
	}

	delta := w.highest - counter
	if delta < 64 {
		w.bits[0] |= uint64(1) << delta
	} else {
		w.bits[1] |= uint64(1) << (delta - 64)
	}
	return true
}
