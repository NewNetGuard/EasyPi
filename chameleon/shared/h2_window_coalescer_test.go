package shared

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func settingsFrame(initialWindow uint32) []byte {
	frame := []byte{0, 0, 6, h2SettingsFrameType, 0, 0, 0, 0, 0, 0, h2SettingsInitialWindow}
	return binary.BigEndian.AppendUint32(frame, initialWindow)
}

func windowUpdateFrame(streamID, credit uint32) []byte {
	return appendWindowUpdate(nil, streamID, int64(credit))
}

func dataFrame(streamID uint32, payload []byte) []byte {
	frame := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), 0x0, 0}
	frame = binary.BigEndian.AppendUint32(frame, streamID)
	return append(frame, payload...)
}

// windowCredits returns the total credit per stream and the number of
// WINDOW_UPDATE frames in a framed byte stream (preface optional).
func windowCredits(t *testing.T, wire []byte) (map[uint32]int64, int) {
	t.Helper()
	wire = bytes.TrimPrefix(wire, h2ClientPreface)
	credits := map[uint32]int64{}
	frames := 0
	for len(wire) > 0 {
		if len(wire) < h2FrameHeaderSize {
			t.Fatalf("truncated frame header: %x", wire)
		}
		length := int(wire[0])<<16 | int(wire[1])<<8 | int(wire[2])
		if len(wire) < h2FrameHeaderSize+length {
			t.Fatalf("truncated frame payload")
		}
		if wire[3] == h2WindowUpdateFrameType {
			frames++
			streamID := binary.BigEndian.Uint32(wire[5:9]) & 0x7fffffff
			credits[streamID] += int64(binary.BigEndian.Uint32(wire[9:13]) & 0x7fffffff)
		}
		wire = wire[h2FrameHeaderSize+length:]
	}
	return credits, frames
}

func TestWindowCoalescerHoldsCreditUntilHalfWindow(t *testing.T) {
	coalescer := newH2WindowCoalescer()
	opening := append(append(append([]byte{}, h2ClientPreface...), settingsFrame(6<<20)...),
		windowUpdateFrame(0, (15<<20)-65535)...)
	if got := coalescer.process(opening); !bytes.Equal(got, opening) {
		t.Fatal("preface, SETTINGS and the opening connection window must pass unchanged")
	}

	var wire []byte
	const step = 4 << 10
	const total = 20 << 20
	for sent := 0; sent < total; sent += step {
		wire = append(wire, coalescer.process(append(windowUpdateFrame(0, step), windowUpdateFrame(1, step)...))...)
	}
	credits, frames := windowCredits(t, wire)
	// 20 MiB of reads: the stream is released every 3 MiB, the connection every 7.5 MiB.
	if frames != 6+2 {
		t.Fatalf("got %d WINDOW_UPDATE frames, want 8 instead of x/net's 10240", frames)
	}
	held := coalescer.held[1].credit
	if credits[1]+held != total || credits[1] != 6*(3<<20) {
		t.Fatalf("stream credit sent=%d held=%d, want all %d accounted for", credits[1], held, total)
	}
	if credits[0]+coalescer.held[0].credit != total {
		t.Fatalf("connection credit lost: sent=%d held=%d", credits[0], coalescer.held[0].credit)
	}
}

func TestWindowCoalescerOutputDoesNotDependOnWriteBoundaries(t *testing.T) {
	var input []byte
	input = append(input, h2ClientPreface...)
	input = append(input, settingsFrame(1<<20)...)
	input = append(input, windowUpdateFrame(0, 1<<20)...)
	// DATA whose payload looks like WINDOW_UPDATE frames must never be parsed.
	input = append(input, dataFrame(3, bytes.Repeat(windowUpdateFrame(3, 1<<30), 40))...)
	for index := 0; index < 600; index++ {
		input = append(input, windowUpdateFrame(uint32(1+2*(index%3)), 4096)...)
	}

	whole := newH2WindowCoalescer().process(input)
	split := newH2WindowCoalescer()
	var pieces []byte
	for _, b := range input {
		pieces = append(pieces, split.process([]byte{b})...)
	}
	if !bytes.Equal(whole, pieces) {
		t.Fatal("byte-by-byte writes must produce the same wire output as one write")
	}
	if !bytes.Contains(whole, dataFrame(3, bytes.Repeat(windowUpdateFrame(3, 1<<30), 40))) {
		t.Fatal("DATA frame changed")
	}
}

func TestWindowCoalescerServerSideAndBoundedStreams(t *testing.T) {
	coalescer := newH2WindowCoalescer()
	opening := append(settingsFrame(16<<20), windowUpdateFrame(0, (16<<20)-65535)...)
	if got := coalescer.process(opening); !bytes.Equal(got, opening) {
		t.Fatal("a server's SETTINGS and opening window must pass unchanged")
	}
	var wire []byte
	for streamID := uint32(1); streamID <= 2*h2MaxHeldStreams+1; streamID += 2 {
		wire = append(wire, coalescer.process(windowUpdateFrame(streamID, 4096))...)
	}
	if coalescer.heldStreams() > h2MaxHeldStreams {
		t.Fatalf("holding %d streams, limit %d", coalescer.heldStreams(), h2MaxHeldStreams)
	}
	credits, _ := windowCredits(t, wire)
	released := int64(0)
	for _, credit := range credits {
		released += credit
	}
	heldCredit := int64(0)
	for streamID, entry := range coalescer.held {
		if streamID != 0 {
			heldCredit += entry.credit
		}
	}
	if released+heldCredit != int64(h2MaxHeldStreams+1)*4096 {
		t.Fatal("evicted stream credit must be released, not dropped")
	}
	if credits[1] != 4096 {
		t.Fatal("the oldest stream should be released first")
	}
}

func TestWindowCoalescerPassesZeroIncrement(t *testing.T) {
	coalescer := newH2WindowCoalescer()
	frame := windowUpdateFrame(5, 0)
	if got := coalescer.process(frame); !bytes.Equal(got, frame) {
		t.Fatal("a zero increment must reach the peer unchanged")
	}
}

// recordingConn keeps the plaintext a carrier endpoint sends.
type recordingConn struct {
	net.Conn
	mu    sync.Mutex
	wrote []byte
}

func (c *recordingConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	c.wrote = append(c.wrote, payload...)
	c.mu.Unlock()
	return c.Conn.Write(payload)
}

func (c *recordingConn) ConnectionState() tls.ConnectionState {
	return c.Conn.(*tls.Conn).ConnectionState()
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "carrier"},
		DNSNames:     []string{"carrier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (c *recordingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wrote...)
}

// End to end through real x/net/http2 peers: a 64 MiB download arrives intact,
// does not stall, and the client acknowledges it the browser way.
func TestCoalescedCarrierDownloadsWithoutStallOrLoss(t *testing.T) {
	const size = 64 << 20
	body := bytes.Repeat([]byte("chameleon-window-coalescing-"), size/28+1)[:size]
	want := sha256.Sum256(body)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http2.Server{MaxUploadBufferPerConnection: 16 << 20, MaxUploadBufferPerStream: 16 << 20}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	certificate := selfSignedCertificate(t)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				// As in production: TLS below, the shaper between TLS and HTTP/2.
				tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}})
				if tlsConn.Handshake() != nil {
					return
				}
				server.ServeConn(NewRecordShapingConn(tlsConn, RecordShapingOptions{
					SenderPacingMode:           SenderPacingRecordOnly,
					CoalesceHTTP2WindowUpdates: true,
				}), &http2.ServeConnOpts{Handler: handler})
			}()
		}
	}()

	var client *recordingConn
	configSource := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: (15 << 20) - 65535,
		MaxReceiveBufferPerStream:     6 << 20,
	}}
	transport, err := http2.ConfigureTransports(configSource)
	if err != nil {
		t.Fatal(err)
	}
	transport.ConnPool = nil
	// The client's header and frame limits as in clientcore/fingerprint.go.
	transport.MaxReadFrameSize = 16 << 10
	transport.MaxHeaderListSize = 256 << 10
	transport.MaxDecoderHeaderTableSize = 64 << 10
	transport.MaxEncoderHeaderTableSize = 64 << 10
	transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		// Record the plaintext the shaper hands to TLS: what the wire carries.
		client = &recordingConn{Conn: tlsConn}
		return NewRecordShapingConn(client, RecordShapingOptions{
			SenderPacingMode:           SenderPacingRecordOnly,
			CoalesceHTTP2WindowUpdates: true,
		}), nil
	}
	defer transport.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://carrier/download", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	copied, err := io.Copy(digest, response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("download stalled or failed after %d bytes: %v", copied, err)
	}
	if copied != size || !bytes.Equal(digest.Sum(nil), want[:]) {
		t.Fatalf("download corrupted: %d bytes", copied)
	}

	_, frames := windowCredits(t, client.written()[:clientFramedPrefix(client.written())])
	// x/net alone sends one per body read here, about 4 000 for 64 MiB.
	if frames > 64 {
		t.Fatalf("client sent %d WINDOW_UPDATE frames for 64 MiB, want browser-like rarity", frames)
	}

	// The real x/net client's opening, as handed to TLS: preface, SETTINGS
	// with Chromium's four entries, connection WINDOW_UPDATE. That is the 70
	// plaintext bytes of Chromium's first record after the handshake.
	opening := client.written()
	settings := opening[len(h2ClientPreface):]
	settingsLength := int(settings[0])<<16 | int(settings[1])<<8 | int(settings[2])
	if settings[3] != h2SettingsFrameType || settingsLength != 4*h2SettingSize {
		t.Fatalf("opening SETTINGS carry %d bytes, want Chromium's 4 entries", settingsLength)
	}
	// HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE.
	ids := settingIDs(settings[h2FrameHeaderSize : h2FrameHeaderSize+settingsLength])
	if !ids[0x1] || !ids[0x2] || !ids[h2SettingsInitialWindow] || !ids[0x6] {
		t.Fatalf("opening SETTINGS differ from Chromium's: %x", settings[:h2FrameHeaderSize+settingsLength])
	}
	rest := settings[h2FrameHeaderSize+settingsLength:]
	if len(rest) < h2WindowUpdateFrameSize || rest[3] != h2WindowUpdateFrameType ||
		len(h2ClientPreface)+h2FrameHeaderSize+settingsLength+h2WindowUpdateFrameSize != 70 {
		t.Fatal("the opening must be preface, SETTINGS and the connection WINDOW_UPDATE, 70 bytes")
	}
}

func settingIDs(payload []byte) map[uint16]bool {
	ids := map[uint16]bool{}
	for ; len(payload) >= h2SettingSize; payload = payload[h2SettingSize:] {
		ids[binary.BigEndian.Uint16(payload)] = true
	}
	return ids
}

func settingsFrameOf(flags byte, entries ...[2]uint32) []byte {
	frame := []byte{0, 0, byte(len(entries) * h2SettingSize), h2SettingsFrameType, flags, 0, 0, 0, 0}
	for _, entry := range entries {
		frame = binary.BigEndian.AppendUint16(frame, uint16(entry[0]))
		frame = binary.BigEndian.AppendUint32(frame, entry[1])
	}
	return frame
}

func TestOpeningSettingsDropOnlyTheDefaultFrameSize(t *testing.T) {
	goSettings := settingsFrameOf(0,
		[2]uint32{0x2, 0}, [2]uint32{h2SettingsInitialWindow, 6 << 20},
		[2]uint32{h2SettingsMaxFrameSize, h2DefaultMaxFrameSize},
		[2]uint32{0x6, 256 << 10}, [2]uint32{0x1, 64 << 10})
	chromium := settingsFrameOf(0,
		[2]uint32{0x2, 0}, [2]uint32{h2SettingsInitialWindow, 6 << 20},
		[2]uint32{0x6, 256 << 10}, [2]uint32{0x1, 64 << 10})
	later := settingsFrameOf(0, [2]uint32{h2SettingsMaxFrameSize, h2DefaultMaxFrameSize})
	ack := settingsFrameOf(h2SettingsAckFlag)

	client := newH2WindowCoalescer()
	input := append(append(append(append([]byte{}, h2ClientPreface...), goSettings...), ack...), later...)
	want := append(append(append(append([]byte{}, h2ClientPreface...), chromium...), ack...), later...)
	if got := client.process(input); !bytes.Equal(got, want) {
		t.Fatalf("client opening:\n got %x\nwant %x", got, want)
	}
	if client.streamWindow != 6<<20 {
		t.Fatal("the initial window must still be read from the rewritten SETTINGS")
	}

	// Byte-by-byte writes give the same result.
	split := newH2WindowCoalescer()
	var pieces []byte
	for _, b := range input {
		pieces = append(pieces, split.process([]byte{b})...)
	}
	if !bytes.Equal(pieces, want) {
		t.Fatal("the rewrite must not depend on write boundaries")
	}

	// A non-default frame size is a real preference and stays.
	custom := settingsFrameOf(0, [2]uint32{h2SettingsMaxFrameSize, 1 << 20})
	if got := newH2WindowCoalescer().process(append(append([]byte{}, h2ClientPreface...), custom...)); !bytes.Equal(got[len(h2ClientPreface):], custom) {
		t.Fatal("a non-default SETTINGS_MAX_FRAME_SIZE must be kept")
	}

	// The server side has no preface and is never rewritten.
	if got := newH2WindowCoalescer().process(goSettings); !bytes.Equal(got, goSettings) {
		t.Fatal("server SETTINGS must pass unchanged")
	}
}

// clientFramedPrefix trims a trailing partial frame that may still be in flight.
func clientFramedPrefix(wire []byte) int {
	offset := 0
	if bytes.HasPrefix(wire, h2ClientPreface) {
		offset = len(h2ClientPreface)
	}
	for offset+h2FrameHeaderSize <= len(wire) {
		length := int(wire[offset])<<16 | int(wire[offset+1])<<8 | int(wire[offset+2])
		if offset+h2FrameHeaderSize+length > len(wire) {
			break
		}
		offset += h2FrameHeaderSize + length
	}
	return offset
}
