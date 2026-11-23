package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"chameleon/prismlink"
)

const (
	prismLinkIdleTimeout = 2 * time.Minute
	prismLinkReadBuffer  = 4 * 1024 * 1024
	// After a rekey the replaced session still accepts packets that were in
	// flight when the phone switched keys.
	prismLinkRekeyGrace = 10 * time.Second
)

type prismLinkPeer struct {
	session  *prismlink.Session
	endpoint *net.UDPAddr
	lastSeen time.Time
	created  time.Time
	retireAt time.Time
}

type prismLinkHelloResult struct {
	peer     *prismLinkPeer
	response []byte
	expires  time.Time
}

type prismLinkServer struct {
	conn        *net.UDPConn
	tun         *kernelTunnel
	credentials *cryptoSessionManager

	mu        sync.RWMutex
	peers     map[uint64]*prismLinkPeer
	byIP      map[[4]byte]*prismLinkPeer
	handshake map[[32]byte]prismLinkHelloResult
	closed    chan struct{}
}

func startPrismLinkServer(address string, credentials *cryptoSessionManager, tun *kernelTunnel) (*prismLinkServer, error) {
	if credentials == nil || tun == nil {
		return nil, errors.New("PrismLink requires credentials and a kernel tunnel")
	}
	listen, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve PrismLink listener: %w", err)
	}
	conn, err := net.ListenUDP("udp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen for PrismLink: %w", err)
	}
	_ = conn.SetReadBuffer(prismLinkReadBuffer)
	_ = conn.SetWriteBuffer(prismLinkReadBuffer)
	server := &prismLinkServer{
		conn:        conn,
		tun:         tun,
		credentials: credentials,
		peers:       make(map[uint64]*prismLinkPeer),
		byIP:        make(map[[4]byte]*prismLinkPeer),
		handshake:   make(map[[32]byte]prismLinkHelloResult),
		closed:      make(chan struct{}),
	}
	go server.readLoop()
	go server.cleanupLoop()
	return server, nil
}

func (server *prismLinkServer) Close() error {
	if server == nil {
		return nil
	}
	select {
	case <-server.closed:
		return nil
	default:
		close(server.closed)
		return server.conn.Close()
	}
}

func (server *prismLinkServer) readLoop() {
	buffer := make([]byte, prismlink.MaxDatagram)
	for {
		n, endpoint, err := server.conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logRateLimitedEvent("prismlink", "UDP receive failed")
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		if !prismlink.IsPacket(packet) {
			continue
		}
		if sessionID, ok := prismlink.SessionID(packet); ok {
			server.handleSessionPacket(sessionID, packet, endpoint)
			continue
		}
		server.handleClientHello(packet, endpoint)
	}
}

func (server *prismLinkServer) handleClientHello(packet []byte, endpoint *net.UDPAddr) {
	digest := sha256.Sum256(packet)
	now := time.Now()
	server.mu.RLock()
	cached, ok := server.handshake[digest]
	server.mu.RUnlock()
	if ok && now.Before(cached.expires) {
		// A captured hello may be replayed, so it can request another copy of
		// the public response but cannot migrate the established path. Only an
		// authenticated session packet is allowed to update the endpoint.
		_, _ = server.conn.WriteToUDP(cached.response, endpoint)
		return
	}

	session, response, err := prismlink.AcceptClientHello(packet, server.credentials.prismLinkCredential, now)
	if err != nil {
		return
	}
	peer := &prismLinkPeer{session: session, endpoint: cloneUDPAddr(endpoint), lastSeen: now, created: now}
	address := session.Address()
	server.mu.Lock()
	server.peers[session.ID()] = peer
	// Make before break: an established session keeps carrying downlink
	// traffic until the phone proves it holds the new keys (see promote).
	if server.byIP[address] == nil {
		server.byIP[address] = peer
	}
	server.handshake[digest] = prismLinkHelloResult{
		peer: peer, response: append([]byte(nil), response...), expires: now.Add(prismlink.HandshakeTTL * time.Second),
	}
	server.mu.Unlock()
	_, _ = server.conn.WriteToUDP(response, endpoint)
}

func (server *prismLinkServer) handleSessionPacket(sessionID uint64, packet []byte, endpoint *net.UDPAddr) {
	server.mu.RLock()
	peer := server.peers[sessionID]
	server.mu.RUnlock()
	if peer == nil {
		return
	}
	if _, ok := server.credentials.prismLinkCredential(peer.session.ClientID()); !ok {
		server.remove(peer)
		return
	}
	typ, payload, err := peer.session.Open(packet)
	if err != nil {
		return
	}
	now := time.Now()
	server.bindEndpoint(peer, endpoint, now)
	switch typ {
	case prismlink.PacketData:
		normalized, err := trimIPv4Packet(payload)
		if err != nil {
			return
		}
		source, _, err := parseIPv4SrcDst(normalized)
		assigned := peer.session.Address()
		if err != nil || !source.Equal(net.IP(assigned[:])) {
			return
		}
		if err := server.tun.WritePacket(normalized); err != nil {
			logRateLimitedEvent("prismlink", "kernel tunnel write failed")
		}
	case prismlink.PacketPing:
		response, err := peer.session.Seal(prismlink.PacketPong, payload)
		if err == nil {
			_, _ = server.conn.WriteToUDP(response, endpoint)
		}
	}
}

func (server *prismLinkServer) bindEndpoint(peer *prismLinkPeer, endpoint *net.UDPAddr, now time.Time) {
	server.mu.Lock()
	if server.peers[peer.session.ID()] == peer {
		peer.endpoint = cloneUDPAddr(endpoint)
		peer.lastSeen = now
		server.promoteLocked(peer, now)
	}
	server.mu.Unlock()
}

// promoteLocked moves downlink delivery to a newer authenticated session and
// schedules the session it replaces for removal after a short grace period.
func (server *prismLinkServer) promoteLocked(peer *prismLinkPeer, now time.Time) {
	address := peer.session.Address()
	current := server.byIP[address]
	if current == peer || (current != nil && current.created.After(peer.created)) {
		return
	}
	if current != nil {
		current.retireAt = now.Add(prismLinkRekeyGrace)
	}
	peer.retireAt = time.Time{}
	server.byIP[address] = peer
}

func (server *prismLinkServer) deliver(packet []byte, destination net.IP) bool {
	destination4 := destination.To4()
	if destination4 == nil {
		return false
	}
	var key [4]byte
	copy(key[:], destination4)
	server.mu.RLock()
	peer := server.byIP[key]
	if peer == nil || time.Since(peer.lastSeen) > prismLinkIdleTimeout {
		server.mu.RUnlock()
		return false
	}
	endpoint := cloneUDPAddr(peer.endpoint)
	server.mu.RUnlock()
	sealed, err := peer.session.Seal(prismlink.PacketData, packet)
	if err != nil || endpoint == nil {
		return true
	}
	_, _ = server.conn.WriteToUDP(sealed, endpoint)
	return true
}

func (server *prismLinkServer) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-server.closed:
			return
		case now := <-ticker.C:
			server.mu.Lock()
			for id, peer := range server.peers {
				retired := !peer.retireAt.IsZero() && now.After(peer.retireAt)
				if retired || now.Sub(peer.lastSeen) > prismLinkIdleTimeout {
					delete(server.peers, id)
					address := peer.session.Address()
					if server.byIP[address] == peer {
						delete(server.byIP, address)
					}
				}
			}
			for digest, result := range server.handshake {
				if now.After(result.expires) {
					delete(server.handshake, digest)
				}
			}
			server.mu.Unlock()
		}
	}
}

func (server *prismLinkServer) remove(peer *prismLinkPeer) {
	server.mu.Lock()
	delete(server.peers, peer.session.ID())
	address := peer.session.Address()
	if server.byIP[address] == peer {
		delete(server.byIP, address)
	}
	server.mu.Unlock()
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
