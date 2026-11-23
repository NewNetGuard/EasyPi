package shared

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"golang.org/x/crypto/hkdf"
)

// TCP streams carry one device TCP connection per HTTP/2 request: the request
// body is the client-to-site byte stream and the response body is the
// site-to-client byte stream. The gateway terminates the device's TCP, so the
// device's TCP acknowledgements never enter the carrier.
//
// Wire format of both bodies: a stream nonce (request only, 16 bytes in the
// clear), then frames of [4-byte big-endian length][inner ciphertext]. The
// first request frame's plaintext names the destination. Each stream has its
// own keys derived from the session's StreamKey and the stream nonce, so
// independent streams never share an inner-cipher counter.
const (
	EndpointSuffixTCP = "/tcp"

	// TCPStreamHeader advertises (server, on sync) and requests (client) the
	// TCP stream capability.
	TCPStreamHeader  = "X-Chameleon-Tcp"
	TCPStreamVersion = "1"

	TCPStreamNonceSize = 16
	// TCPStreamMaxPlaintext bounds one frame so a peer cannot force large
	// allocations; it matches an HTTP/2 DATA frame of the default size.
	TCPStreamMaxPlaintext = 16 << 10

	tcpStreamTargetVersion = 1
	tcpStreamTargetSize    = 1 + 4 + 2
)

var ErrTCPStreamFrameTooLarge = errors.New("tcp stream frame too large")

// NewTCPStreamCipher derives the ciphers of one stream. The client sends with
// the client-to-server key; the server with the server-to-client key.
func NewTCPStreamCipher(streamKey []byte, sessionID string, streamNonce []byte, isClient bool) (*InnerCipher, error) {
	if len(streamKey) != 32 {
		return nil, fmt.Errorf("tcp stream key must contain 32 bytes")
	}
	if len(streamNonce) != TCPStreamNonceSize || sessionID == "" {
		return nil, fmt.Errorf("tcp stream context is incomplete")
	}
	reader := hkdf.New(sha256.New, streamKey, streamNonce, sessionFields(SessionProtocolID+"/tcp-stream", sessionID))
	material := make([]byte, 32+32+16+16)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, fmt.Errorf("derive tcp stream keys: %w", err)
	}
	c2sKey, s2cKey := material[0:32], material[32:64]
	c2sPrefix, s2cPrefix := material[64:80], material[80:96]
	context := sessionID + ":" + hex.EncodeToString(streamNonce)
	if isClient {
		return NewInnerCipher(c2sKey, s2cKey, c2sPrefix, s2cPrefix, context, "tcp-c2s", "tcp-s2c")
	}
	return NewInnerCipher(s2cKey, c2sKey, s2cPrefix, c2sPrefix, context, "tcp-s2c", "tcp-c2s")
}

// EncodeTCPStreamTarget encodes the destination carried in the first frame.
func EncodeTCPStreamTarget(target netip.AddrPort) ([]byte, error) {
	addr := target.Addr().Unmap()
	if !addr.Is4() || target.Port() == 0 {
		return nil, fmt.Errorf("tcp stream target must be IPv4 with a port")
	}
	out := make([]byte, tcpStreamTargetSize)
	out[0] = tcpStreamTargetVersion
	a := addr.As4()
	copy(out[1:5], a[:])
	binary.BigEndian.PutUint16(out[5:7], target.Port())
	return out, nil
}

// DecodeTCPStreamTarget parses the destination from the first frame.
func DecodeTCPStreamTarget(payload []byte) (netip.AddrPort, error) {
	if len(payload) != tcpStreamTargetSize || payload[0] != tcpStreamTargetVersion {
		return netip.AddrPort{}, fmt.Errorf("malformed tcp stream target")
	}
	addr := netip.AddrFrom4([4]byte(payload[1:5]))
	port := binary.BigEndian.Uint16(payload[5:7])
	if port == 0 {
		return netip.AddrPort{}, fmt.Errorf("malformed tcp stream target")
	}
	return netip.AddrPortFrom(addr, port), nil
}

// Stream shaping. Without it every frame carries exactly its payload, so each
// record of a tunnelled TLS handshake (ClientHello, the server's flight, the
// client Finished) surfaces in an outer TLS record of exactly its own size
// plus a constant, the core feature of TLS-in-TLS classifiers. A shaped
// stream frames its plaintext as [2-byte data length][data][padding] and pads
// only the opening frames of each direction, where handshakes live:
//
//   - small frames (the destination, a Finished, short requests) to a random
//     size up to tcpStreamShapeSmallCap, like the small requests and control
//     records of an ordinary HTTP/2 page;
//   - the first larger frame (a ClientHello upstream, the server's handshake
//     flight downstream) to a random size up to a direction-specific cap;
//   - nothing else: later frames and every bulk transfer go unpadded.
//
// The target is uniform between the frame's own size and the cap, so one
// observed record leaves a wide range of possible inner sizes without
// forming a fixed band of its own. The rule and its cost were chosen from a
// model of leaked size against padding bytes; see the measurement test.
const (
	// TCPStreamShapeHeader advertises (server, on sync) and requests (client,
	// per stream) shaped framing. Peers without it use plain frames.
	TCPStreamShapeHeader  = "X-Chameleon-Tcp-Shape"
	TCPStreamShapeVersion = "1"

	tcpStreamShapedFrames    = 4
	tcpStreamShapeSmall      = 512
	tcpStreamShapeSmallCap   = 576
	tcpStreamShapeUpstream   = 4096
	tcpStreamShapeDownstream = 8192
	tcpStreamShapePrefix     = 2
)

// TCPStreamFramer writes and reads the frames of one stream.
type TCPStreamFramer struct {
	cipher   *InnerCipher
	shaped   bool
	largeCap int  // cap for the first larger frame this side sends
	sent     int  // frames sent so far
	large    bool // the first larger frame has been shaped
	scratch  []byte
}

// NewTCPStreamFramer returns the framer of one stream end; client is true for
// the device side, which sends upstream.
func NewTCPStreamFramer(cipher *InnerCipher, shaped, client bool) *TCPStreamFramer {
	largeCap := tcpStreamShapeDownstream
	if client {
		largeCap = tcpStreamShapeUpstream
	}
	return &TCPStreamFramer{cipher: cipher, shaped: shaped, largeCap: largeCap}
}

// MaxData is the most payload one frame carries: a full frame in both
// formats, so shaping never splits a write into an extra small frame. The
// 2-byte length prefix fits in the frame size slack readers already allow.
func (f *TCPStreamFramer) MaxData() int {
	return TCPStreamMaxPlaintext
}

// padding returns the padding for the next frame of n data bytes.
func (f *TCPStreamFramer) padding(n int) int {
	if !f.shaped || f.sent >= tcpStreamShapedFrames {
		return 0
	}
	f.sent++
	limit := 0
	switch {
	case n <= tcpStreamShapeSmall:
		limit = tcpStreamShapeSmallCap
	case !f.large:
		f.large = true
		limit = f.largeCap
	}
	if limit <= n {
		return 0
	}
	var entropy [4]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return 0
	}
	pad := int(binary.BigEndian.Uint32(entropy[:]) % uint32(limit-n+1))
	return min(pad, TCPStreamMaxPlaintext-n)
}

// AppendFrame encrypts data as one frame and appends it to out, so several
// frames can leave in a single write.
func (f *TCPStreamFramer) AppendFrame(out, data []byte) ([]byte, error) {
	if len(data) > f.MaxData() {
		return nil, ErrTCPStreamFrameTooLarge
	}
	plaintext := data
	if f.shaped {
		// The writer side is used by one goroutine at a time (the stream's
		// write lock), so one scratch buffer serves every frame.
		size := tcpStreamShapePrefix + len(data) + f.padding(len(data))
		if cap(f.scratch) < size {
			f.scratch = make([]byte, size, max(size, tcpStreamShapePrefix+TCPStreamMaxPlaintext))
		}
		plaintext = f.scratch[:size]
		binary.BigEndian.PutUint16(plaintext, uint16(len(data)))
		copy(plaintext[tcpStreamShapePrefix:], data)
		clear(plaintext[tcpStreamShapePrefix+len(data):])
	}
	sealed, err := f.cipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = make([]byte, 0, 4+len(sealed))
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(sealed)))
	return append(out, sealed...), nil
}

// WriteFrame encrypts data as one frame and writes it.
func (f *TCPStreamFramer) WriteFrame(w io.Writer, data []byte) error {
	frame, err := f.AppendFrame(nil, data)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// ReadFrame reads one frame and returns its data. io.EOF means the peer ended
// the stream cleanly between frames.
func (f *TCPStreamFramer) ReadFrame(r io.Reader) ([]byte, error) {
	plaintext, err := ReadTCPStreamFrame(r, f.cipher)
	if err != nil || !f.shaped {
		return plaintext, err
	}
	if len(plaintext) < tcpStreamShapePrefix {
		return nil, errMalformedShapedFrame
	}
	n := int(binary.BigEndian.Uint16(plaintext))
	if n > len(plaintext)-tcpStreamShapePrefix {
		return nil, errMalformedShapedFrame
	}
	return plaintext[tcpStreamShapePrefix : tcpStreamShapePrefix+n], nil
}

var errMalformedShapedFrame = errors.New("malformed shaped tcp stream frame")

// WriteTCPStreamFrame encrypts plaintext and writes one frame.
func WriteTCPStreamFrame(w io.Writer, cipher *InnerCipher, plaintext []byte) error {
	if len(plaintext) > TCPStreamMaxPlaintext {
		return ErrTCPStreamFrameTooLarge
	}
	sealed, err := cipher.Encrypt(plaintext)
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(sealed)))
	copy(frame[4:], sealed)
	_, err = w.Write(frame)
	return err
}

// ReadTCPStreamFrame reads and decrypts one frame. io.EOF means the peer ended
// the stream cleanly between frames.
func ReadTCPStreamFrame(r io.Reader, cipher *InnerCipher) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > TCPStreamMaxPlaintext+innerCounterSize+64 {
		return nil, ErrTCPStreamFrameTooLarge
	}
	sealed := make([]byte, length)
	if _, err := io.ReadFull(r, sealed); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return cipher.Decrypt(sealed)
}
