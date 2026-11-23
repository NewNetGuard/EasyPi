package prismlink

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	clientHelloBodySize = 16 + 32 + 16 + 8 + 32
	serverHelloBodySize = 32 + 16 + 8 + 32
)

var (
	clientHelloContext = []byte("easypi/prismlink/client-hello/v1")
	serverHelloContext = []byte("easypi/prismlink/server-hello/v1")
	keyContext         = []byte("easypi/prismlink/session-keys/v1")
)

type Credential struct {
	ClientID [16]byte
	PSK      [32]byte
	Address  [4]byte
}

type CredentialLookup func(clientID [16]byte) (Credential, bool)

type ClientHandshake struct {
	credential Credential
	privateKey *ecdh.PrivateKey
	hello      []byte
}

type Session struct {
	id       uint64
	clientID [16]byte
	address  [4]byte
	send     cipherState
	receive  cipherState
	next     atomic.Uint64
	replay   replayWindow
}

type cipherState struct {
	mu   sync.Mutex
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	marker uint32
}

func NewClientHandshake(credential Credential, now time.Time) (*ClientHandshake, []byte, error) {
	if credential.ClientID == [16]byte{} || credential.PSK == [32]byte{} || credential.Address == [4]byte{} {
		return nil, nil, errors.New("invalid PrismLink client credential")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate PrismLink ephemeral key: %w", err)
	}
	packet := make([]byte, HeaderSize+clientHelloBodySize)
	if err := encodeHeader(packet, header{typ: PacketClientHello}); err != nil {
		return nil, nil, err
	}
	body := packet[HeaderSize:]
	copy(body[:16], credential.ClientID[:])
	copy(body[16:48], privateKey.PublicKey().Bytes())
	if _, err := rand.Read(body[48:64]); err != nil {
		return nil, nil, fmt.Errorf("generate PrismLink hello nonce: %w", err)
	}
	binary.BigEndian.PutUint64(body[64:72], uint64(now.Unix()))
	copy(body[72:], authenticationTag(credential.PSK[:], clientHelloContext, packet[:HeaderSize+72]))
	return &ClientHandshake{credential: credential, privateKey: privateKey, hello: append([]byte(nil), packet...)}, packet, nil
}

func AcceptClientHello(packet []byte, lookup CredentialLookup, now time.Time) (*Session, []byte, error) {
	headerValue, err := decodeHeader(packet)
	if err != nil || headerValue.typ != PacketClientHello || headerValue.sessionID != 0 || headerValue.sequence != 0 || len(packet) != HeaderSize+clientHelloBodySize {
		return nil, nil, errors.New("invalid PrismLink client hello")
	}
	body := packet[HeaderSize:]
	var clientID [16]byte
	copy(clientID[:], body[:16])
	credential, ok := lookup(clientID)
	if !ok || credential.ClientID != clientID {
		return nil, nil, errors.New("unknown PrismLink client")
	}
	timestamp := int64(binary.BigEndian.Uint64(body[64:72]))
	if delta := now.Sub(time.Unix(timestamp, 0)); delta < -HandshakeTTL*time.Second || delta > HandshakeTTL*time.Second {
		return nil, nil, errors.New("PrismLink client hello is outside the authentication window")
	}
	expected := authenticationTag(credential.PSK[:], clientHelloContext, packet[:HeaderSize+72])
	if !hmac.Equal(expected, body[72:]) {
		return nil, nil, errors.New("invalid PrismLink client authenticator")
	}
	clientPublic, err := ecdh.X25519().NewPublicKey(body[16:48])
	if err != nil {
		return nil, nil, errors.New("invalid PrismLink client key")
	}
	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate PrismLink server key: %w", err)
	}
	sharedSecret, err := serverPrivate.ECDH(clientPublic)
	if err != nil {
		return nil, nil, errors.New("invalid PrismLink key agreement")
	}
	sessionID, err := randomUint64()
	if err != nil {
		return nil, nil, err
	}
	response := make([]byte, HeaderSize+serverHelloBodySize)
	_ = encodeHeader(response, header{typ: PacketServerHello, sessionID: sessionID})
	responseBody := response[HeaderSize:]
	copy(responseBody[:32], serverPrivate.PublicKey().Bytes())
	if _, err := rand.Read(responseBody[32:48]); err != nil {
		return nil, nil, fmt.Errorf("generate PrismLink server nonce: %w", err)
	}
	binary.BigEndian.PutUint64(responseBody[48:56], uint64(now.Unix()))
	transcript := transcriptHash(packet, response[:HeaderSize+56])
	copy(responseBody[56:], authenticationTag(credential.PSK[:], serverHelloContext, transcript[:]))
	session, err := newSession(sessionID, credential, sharedSecret, transcript[:], false)
	return session, response, err
}

func (handshake *ClientHandshake) Complete(response []byte, now time.Time) (*Session, error) {
	if handshake == nil || handshake.privateKey == nil {
		return nil, errors.New("PrismLink client handshake is unavailable")
	}
	headerValue, err := decodeHeader(response)
	if err != nil || headerValue.typ != PacketServerHello || headerValue.sessionID == 0 || headerValue.sequence != 0 || len(response) != HeaderSize+serverHelloBodySize {
		return nil, errors.New("invalid PrismLink server hello")
	}
	body := response[HeaderSize:]
	timestamp := int64(binary.BigEndian.Uint64(body[48:56]))
	if delta := now.Sub(time.Unix(timestamp, 0)); delta < -HandshakeTTL*time.Second || delta > HandshakeTTL*time.Second {
		return nil, errors.New("PrismLink server hello is outside the authentication window")
	}
	transcript := transcriptHash(handshake.hello, response[:HeaderSize+56])
	expected := authenticationTag(handshake.credential.PSK[:], serverHelloContext, transcript[:])
	if !hmac.Equal(expected, body[56:]) {
		return nil, errors.New("invalid PrismLink server authenticator")
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(body[:32])
	if err != nil {
		return nil, errors.New("invalid PrismLink server key")
	}
	sharedSecret, err := handshake.privateKey.ECDH(serverPublic)
	if err != nil {
		return nil, errors.New("invalid PrismLink key agreement")
	}
	return newSession(headerValue.sessionID, handshake.credential, sharedSecret, transcript[:], true)
}

func newSession(id uint64, credential Credential, sharedSecret, transcript []byte, client bool) (*Session, error) {
	info := append(append([]byte(nil), keyContext...), transcript...)
	reader := hkdf.New(sha256.New, sharedSecret, credential.PSK[:], info)
	keys := make([]byte, 2*chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, keys); err != nil {
		return nil, fmt.Errorf("derive PrismLink session keys: %w", err)
	}
	clientToServer, err := chacha20poly1305.New(keys[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}
	serverToClient, err := chacha20poly1305.New(keys[chacha20poly1305.KeySize:])
	if err != nil {
		return nil, err
	}
	session := &Session{id: id, clientID: credential.ClientID, address: credential.Address}
	if client {
		session.send = cipherState{aead: clientToServer, marker: 0x434c4e54}
		session.receive = cipherState{aead: serverToClient, marker: 0x53525652}
	} else {
		session.send = cipherState{aead: serverToClient, marker: 0x53525652}
		session.receive = cipherState{aead: clientToServer, marker: 0x434c4e54}
	}
	return session, nil
}

func (session *Session) ID() uint64         { return session.id }
func (session *Session) ClientID() [16]byte { return session.clientID }
func (session *Session) Address() [4]byte   { return session.address }

func (session *Session) Seal(typ PacketType, payload []byte) ([]byte, error) {
	if session == nil || session.send.aead == nil || (typ != PacketData && typ != PacketPing && typ != PacketPong && typ != PacketAck) {
		return nil, errors.New("invalid PrismLink encrypted packet")
	}
	if typ == PacketData && (len(payload) == 0 || len(payload) > MaxInnerPacket) {
		return nil, errors.New("invalid PrismLink inner packet size")
	}
	sequence := session.next.Add(1)
	packet := make([]byte, HeaderSize)
	_ = encodeHeader(packet, header{typ: typ, sessionID: session.id, sequence: sequence})
	nonce := packetNonce(session.send.marker, sequence)
	session.send.mu.Lock()
	packet = session.send.aead.Seal(packet, nonce[:], payload, packet[:HeaderSize])
	session.send.mu.Unlock()
	return packet, nil
}

func (session *Session) Open(packet []byte) (PacketType, []byte, error) {
	if session == nil || session.receive.aead == nil || len(packet) < HeaderSize+chacha20poly1305.Overhead {
		return 0, nil, errors.New("invalid PrismLink encrypted packet")
	}
	headerValue, err := decodeHeader(packet)
	if err != nil || headerValue.sessionID != session.id || headerValue.sequence == 0 || headerValue.typ < PacketData || headerValue.typ > PacketAck {
		return 0, nil, errors.New("invalid PrismLink session packet")
	}
	nonce := packetNonce(session.receive.marker, headerValue.sequence)
	session.receive.mu.Lock()
	payload, err := session.receive.aead.Open(nil, nonce[:], packet[HeaderSize:], packet[:HeaderSize])
	session.receive.mu.Unlock()
	if err != nil {
		return 0, nil, errors.New("PrismLink packet authentication failed")
	}
	if !session.replay.accept(headerValue.sequence) {
		return 0, nil, errors.New("PrismLink replay rejected")
	}
	if headerValue.typ == PacketData && (len(payload) == 0 || len(payload) > MaxInnerPacket) {
		return 0, nil, errors.New("invalid PrismLink inner packet")
	}
	return headerValue.typ, payload, nil
}

func authenticationTag(key, context, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(context)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func transcriptHash(clientHello, serverPrefix []byte) [32]byte {
	digest := sha256.New()
	_, _ = digest.Write(clientHello)
	_, _ = digest.Write(serverPrefix)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func packetNonce(marker uint32, sequence uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], marker)
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func randomUint64() (uint64, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, fmt.Errorf("generate PrismLink session id: %w", err)
	}
	result := binary.BigEndian.Uint64(value[:])
	if result == 0 {
		return randomUint64()
	}
	return result, nil
}
