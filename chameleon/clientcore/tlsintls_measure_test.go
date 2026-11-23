package clientcore

// Local measurement of what a passive observer sees of a device's TLS
// connection carried as a Chameleon TCP stream: the outer TLS records (size,
// direction, time) on the client's carrier connection, next to the inner TLS
// records the site exchanges with the device. Run with
//
//	CHAMELEON_MEASURE=1 go test ./clientcore -run Measure -v
//
// The stream server is a faithful copy of server/tcp_stream.go's data path
// (same shared framing, 16 KiB reads, flush per frame). nginx is not in the
// path, so downstream record boundaries are the backend's, not nginx's.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"chameleon/shared"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type tlsRecord struct {
	at   time.Duration
	up   bool // client to server
	size int  // TLS record length including the 5-byte header
	kind byte // record content type (0x16 handshake, 0x17 application data, ...)
}

// recordTap parses the TLS record headers flowing through a connection.
type recordTap struct {
	net.Conn
	start   time.Time
	mu      sync.Mutex
	records []tlsRecord
	upBuf   []byte
	downBuf []byte
	delay   time.Duration // one-way delay added to writes (models the WAN)
}

func (t *recordTap) feed(buf *[]byte, data []byte, up bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	*buf = append(*buf, data...)
	for len(*buf) >= 5 {
		size := 5 + int(binary.BigEndian.Uint16((*buf)[3:5]))
		if len(*buf) < size {
			return
		}
		t.records = append(t.records, tlsRecord{at: time.Since(t.start), up: up, size: size, kind: (*buf)[0]})
		*buf = (*buf)[size:]
	}
}

func (t *recordTap) Write(p []byte) (int, error) {
	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	t.feed(&t.upBuf, p, true)
	return t.Conn.Write(p)
}

func (t *recordTap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.feed(&t.downBuf, p[:n], false)
	}
	return n, err
}

func (t *recordTap) snapshot() []tlsRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]tlsRecord(nil), t.records...)
}

func (t *recordTap) reset() {
	t.mu.Lock()
	t.records = nil
	t.start = time.Now()
	t.mu.Unlock()
}

// siteCertificate builds a chain shaped like a public site's: RSA-2048
// intermediate, ECDSA P-256 leaf.
func siteCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"Measure Root"}, CommonName: "Measure Root CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	inter := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{"Measure Trust Services"}, CommonName: "Measure Intermediate CA R1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		CRLDistributionPoints: []string{"http://crl.measure.example/r1.crl"}, OCSPServer: []string{"http://ocsp.measure.example"}}
	interDER, _ := x509.CreateCertificate(rand.Reader, inter, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "site.example"},
		DNSNames:  []string{"site.example", "www.site.example", "static.site.example", "api.site.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: []string{"http://ocsp.measure.example"}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, interCert, &leafKey.PublicKey, interKey)
	return tls.Certificate{Certificate: [][]byte{leafDER, interDER}, PrivateKey: leafKey}
}

type measureOptions struct {
	wanDelay time.Duration
	shaped   bool // shaped frames negotiated
	early    bool // the relay sends the device's first data with the open
}

type measureEnv struct {
	opts      measureOptions
	relay     net.Listener // the device side: a local relay like the client's
	target    netip.AddrPort
	transport *Transport
	outer     *recordTap
	siteAddr  netip.AddrPort
	inner     chan *recordTap // the site's view of each accepted device connection
	echo      net.Listener    // a plain listener answering "S bytes in, R bytes out"
}

// measureStreamHandler mirrors server/tcp_stream.go's data path.
func measureStreamHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := make([]byte, shared.TCPStreamNonceSize)
		if _, err := io.ReadFull(r.Body, nonce); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cipher, _ := shared.NewTCPStreamCipher(testStreamKey, testStreamSessionID, nonce, false)
		framer := shared.NewTCPStreamFramer(cipher, r.Header.Get(shared.TCPStreamShapeHeader) == shared.TCPStreamShapeVersion, false)
		first, err := framer.ReadFrame(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		target, err := shared.DecodeTCPStreamTarget(first)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upstream, err := net.Dial("tcp4", target.String())
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		controller := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		_ = controller.Flush()
		go func() {
			for {
				payload, err := framer.ReadFrame(r.Body)
				if err != nil {
					if tcp, ok := upstream.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
					return
				}
				if len(payload) > 0 {
					if _, err := upstream.Write(payload); err != nil {
						return
					}
				}
			}
		}()
		buf := make([]byte, framer.MaxData())
		for {
			n, readErr := upstream.Read(buf)
			if n > 0 {
				if framer.WriteFrame(w, buf[:n]) != nil || controller.Flush() != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}
}

func newMeasureEnv(t *testing.T, opts measureOptions) *measureEnv {
	t.Helper()
	env := &measureEnv{opts: opts, inner: make(chan *recordTap, 64)}

	// The site: TLS 1.3 with a public-site-shaped chain, answering one
	// HTTP/1.1 request per connection with a small page.
	cert := siteCertificate(t)
	siteListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { siteListener.Close() })
	env.siteAddr = netip.MustParseAddrPort(siteListener.Addr().String())
	go func() {
		for {
			raw, err := siteListener.Accept()
			if err != nil {
				return
			}
			tap := &recordTap{Conn: raw, start: time.Now()}
			env.inner <- tap
			go func() {
				conn := tls.Server(tap, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, request.Body)
					body := strings.Repeat("x", 3400)
					fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: max-age=600\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				}
			}()
		}
	}()

	// A plain service for the size-leak trials: reads a 4-byte request size,
	// the request, then answers with the requested number of bytes.
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	env.echo = echo
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var hdr [8]byte
				for {
					if _, err := io.ReadFull(conn, hdr[:]); err != nil {
						return
					}
					reqSize, respSize := binary.BigEndian.Uint32(hdr[:4]), binary.BigEndian.Uint32(hdr[4:])
					if _, err := io.CopyN(io.Discard, conn, int64(reqSize)); err != nil {
						return
					}
					if _, err := conn.Write(make([]byte, respSize)); err != nil {
						return
					}
				}
			}()
		}
	}()

	server := httptest.NewUnstartedServer(measureStreamHandler(t))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.ServerName = "example.com" // httptest certificates name example.com
	env.outer = &recordTap{start: time.Now(), delay: opts.wanDelay}
	var once sync.Once
	h2 := &http2.Transport{DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		var conn net.Conn = raw
		once.Do(func() {
			env.outer.Conn = raw
			conn = env.outer
		})
		client := tls.Client(conn, tlsConfig)
		return client, client.HandshakeContext(ctx)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	env.transport = &Transport{
		protocol: "http2", fingerprint: NewFingerprinter(), ctx: ctx, epochCtx: ctx,
		streamClient: &http.Client{Transport: h2}, routeTCP: server.URL + "/tcp",
		streamKey: testStreamKey, sessionID: testStreamSessionID,
	}
	env.transport.tcpStreamEnabled.Store(true)
	env.transport.tcpStreamShaped.Store(opts.shaped)
	env.startRelay(t)
	// Warm the carrier so the measured stream is not mixed with its handshake.
	warm, err := env.transport.OpenTCPStream(context.Background(), netip.MustParseAddrPort(echo.Addr().String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	warm.Close()
	time.Sleep(50 * time.Millisecond)
	return env
}

// startRelay accepts device connections and carries each to env.target the
// way cmd/chameleon-client's relay does, including its early-data read.
func (env *measureEnv) startRelay(t *testing.T) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	env.relay = listener
	go func() {
		for {
			device, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer device.Close()
				var early []byte
				if env.opts.early {
					buf := make([]byte, shared.TCPStreamMaxPlaintext)
					_ = device.SetReadDeadline(time.Now().Add(relayEarlyDataWait))
					n, _ := device.Read(buf)
					_ = device.SetReadDeadline(time.Time{})
					early = buf[:n]
				}
				stream, err := env.transport.OpenTCPStream(context.Background(), env.target, early)
				if err != nil {
					return
				}
				defer stream.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(stream, device); _ = stream.CloseWrite(); done <- struct{}{} }()
				go func() { _, _ = io.Copy(device, stream); _ = device.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
				<-done
				<-done
			}()
		}
	}()
}

// relayEarlyDataWait mirrors the client relay's wait for a device's first data.
const relayEarlyDataWait = 20 * time.Millisecond

func (env *measureEnv) dialDevice(t *testing.T, target netip.AddrPort) net.Conn {
	t.Helper()
	env.target = target
	conn, err := net.Dial("tcp4", env.relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// deviceTLS runs the device side of a page load over one stream: a Chrome 157
// ClientHello handshake, one GET, the response.
func (env *measureEnv) deviceTLS(t *testing.T) (outer []tlsRecord, inner []tlsRecord) {
	t.Helper()
	env.outer.reset()
	conn := env.dialDevice(t, env.siteAddr)
	defer conn.Close()
	spec, err := chrome157ClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	device := utls.UClient(conn, &utls.Config{ServerName: "site.example", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := device.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := device.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(device, "GET / HTTP/1.1\r\nHost: site.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(device), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	time.Sleep(50 * time.Millisecond)
	siteTap := <-env.inner
	return env.outer.snapshot(), siteTap.snapshot()
}

// sizeTrial sends one request of reqSize bytes and reads a response of
// respSize bytes over a fresh stream, and returns the outer records.
func (env *measureEnv) sizeTrial(t *testing.T, reqSize, respSize int) []tlsRecord {
	t.Helper()
	env.outer.reset()
	stream := env.dialDevice(t, netip.MustParseAddrPort(env.echo.Addr().String()))
	defer stream.Close()
	request := make([]byte, 8+reqSize)
	binary.BigEndian.PutUint32(request[:4], uint32(reqSize))
	binary.BigEndian.PutUint32(request[4:8], uint32(respSize))
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, make([]byte, respSize)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	return env.outer.snapshot()
}

func pearson(xs, ys []float64) float64 {
	var sx, sy, sxx, syy, sxy float64
	n := float64(len(xs))
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		syy += ys[i] * ys[i]
		sxy += xs[i] * ys[i]
	}
	den := math.Sqrt((n*sxx - sx*sx) * (n*syy - sy*sy))
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

func largestRecord(records []tlsRecord, up bool) int {
	largest := 0
	for _, r := range records {
		if r.up == up && r.size > largest {
			largest = r.size
		}
	}
	return largest
}

func formatTrace(records []tlsRecord) string {
	var b strings.Builder
	for _, r := range records {
		dir := "down"
		if r.up {
			dir = "up  "
		}
		fmt.Fprintf(&b, "  %7.1f ms  %s  %5d  type %#02x\n", float64(r.at.Microseconds())/1000, dir, r.size, r.kind)
	}
	return b.String()
}

func TestMeasureTLSInTLSOnStreams(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("set CHAMELEON_MEASURE=1 to run the TLS-in-TLS measurement")
	}
	env := newMeasureEnv(t, measureOptions{shaped: os.Getenv("CHAMELEON_MEASURE_SHAPED") != "", early: os.Getenv("CHAMELEON_MEASURE_EARLY") != ""})

	outer, inner := env.deviceTLS(t)
	t.Logf("inner records at the site (device=up):\n%s", formatTrace(inner))
	t.Logf("outer records on the carrier:\n%s", formatTrace(outer))

	// Size leak: does the outer record size follow the inner message size?
	var reqs, ups, resps, downs []float64
	offsetsUp := map[int]int{}
	offsetsDown := map[int]int{}
	for i := 0; i < 60; i++ {
		var r [4]byte
		_, _ = rand.Read(r[:])
		req := 200 + int(binary.BigEndian.Uint16(r[:2]))%2600
		resp := 800 + int(binary.BigEndian.Uint16(r[2:]))%7000
		records := env.sizeTrial(t, req, resp)
		up, down := largestRecord(records, true), largestRecord(records, false)
		reqs, ups = append(reqs, float64(req)), append(ups, float64(up))
		resps, downs = append(resps, float64(resp)), append(downs, float64(down))
		offsetsUp[up-(req+8)]++
		offsetsDown[down-resp]++
	}
	t.Logf("request size -> largest upstream record: r=%.4f, offsets %v", pearson(reqs, ups), topOffsets(offsetsUp))
	t.Logf("response size -> largest downstream record: r=%.4f, offsets %v", pearson(resps, downs), topOffsets(offsetsDown))
}

func topOffsets(m map[int]int) string {
	type kv struct{ k, v int }
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].v > list[b].v })
	var parts []string
	for i, e := range list {
		if i == 4 {
			parts = append(parts, fmt.Sprintf("... %d distinct", len(list)))
			break
		}
		parts = append(parts, fmt.Sprintf("%+d bytes x%d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

// handshakeView picks, from the outer records of one page-load stream, the
// records an observer would use to spot an inner TLS handshake: the first
// large upstream record (the ClientHello), the first large downstream record
// (the server's flight) and the first small upstream record after it (the
// client Finished).
func handshakeView(records []tlsRecord) (clientHello, flight, finished, upBytes, downBytes int) {
	sawFlight := false
	for _, r := range records {
		if r.up {
			upBytes += r.size
		} else {
			downBytes += r.size
		}
		// HTTP/2 control records (WINDOW_UPDATE, PING, SETTINGS ACK) are
		// under 60 bytes; a ClientHello is over 1000 even unpadded.
		switch {
		case r.up && clientHello == 0 && r.size > 1000:
			clientHello = r.size
		case !r.up && flight == 0 && clientHello != 0 && r.size > 600:
			flight, sawFlight = r.size, true
		case r.up && sawFlight && finished == 0 && r.size > 60:
			finished = r.size
		}
	}
	return
}

func summarize(values []int) string {
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	distinct := map[int]bool{}
	for _, v := range values {
		distinct[v] = true
	}
	return fmt.Sprintf("%5d..%-5d (%2d distinct)", sorted[0], sorted[len(sorted)-1], len(distinct))
}

func TestMeasureTLSInTLSSummary(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("set CHAMELEON_MEASURE=1 to run the TLS-in-TLS measurement")
	}
	modes := []struct {
		name string
		opts measureOptions
	}{
		{"current", measureOptions{}},
		{"early data", measureOptions{early: true}},
		{"shaped", measureOptions{shaped: true}},
		{"early + shaped", measureOptions{early: true, shaped: true}},
	}
	const runs = 30
	for _, mode := range modes {
		env := newMeasureEnv(t, mode.opts)
		var hellos, flights, finishes, ups, downs []int
		for i := 0; i < runs; i++ {
			outer, _ := env.deviceTLS(t)
			ch, fl, fin, up, down := handshakeView(outer)
			hellos, flights, finishes = append(hellos, ch), append(flights, fl), append(finishes, fin)
			ups, downs = append(ups, up), append(downs, down)
		}
		var reqs, upsTrial, resps, downsTrial []float64
		for i := 0; i < 60; i++ {
			var r [4]byte
			_, _ = rand.Read(r[:])
			req := 200 + int(binary.BigEndian.Uint16(r[:2]))%2600
			resp := 800 + int(binary.BigEndian.Uint16(r[2:]))%7000
			records := env.sizeTrial(t, req, resp)
			reqs, upsTrial = append(reqs, float64(req)), append(upsTrial, float64(largestRecord(records, true)))
			resps, downsTrial = append(resps, float64(resp)), append(downsTrial, float64(largestRecord(records, false)))
		}
		mean := func(v []int) float64 {
			total := 0
			for _, x := range v {
				total += x
			}
			return float64(total) / float64(len(v))
		}
		t.Logf("%-15s ClientHello %s  flight %s  Finished %s  bytes/stream up %.0f down %.0f  size r up %.2f down %.2f",
			mode.name, summarize(hellos), summarize(flights), summarize(finishes), mean(ups), mean(downs),
			pearson(reqs, upsTrial), pearson(resps, downsTrial))
	}
}

func TestMeasureStreamLatency(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("set CHAMELEON_MEASURE=1 to run the TLS-in-TLS measurement")
	}
	for _, mode := range []struct {
		name string
		opts measureOptions
	}{
		{"current", measureOptions{wanDelay: 25 * time.Millisecond}},
		{"early + shaped", measureOptions{wanDelay: 25 * time.Millisecond, early: true, shaped: true}},
	} {
		env := newMeasureEnv(t, mode.opts)
		var times []time.Duration
		for i := 0; i < 10; i++ {
			start := time.Now()
			env.deviceTLS(t)
			times = append(times, time.Since(start))
		}
		sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
		t.Logf("%-15s page load over one stream (handshake + GET), 25 ms one-way carrier delay: median %v", mode.name, times[len(times)/2].Round(time.Millisecond))
	}
}
