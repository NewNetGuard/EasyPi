package mobilelink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/prismlink"
)

const (
	prismRelayIdleTimeout = 2 * time.Minute
	prismRelayMaxRoutes   = 4096
	prismAgentMaxRoutes   = 256
	// The relay learns the agent's NAT-mapped address only from authenticated
	// registrations, so their interval bounds the outage after a home router
	// rebinds the agent's UDP port.
	prismAgentRegisterInterval = 5 * time.Second
)

// resolvePrismRelay is replaced in tests.
var resolvePrismRelay = net.ResolveUDPAddr

type PrismSecretLookup func(installationID [16]byte) ([32]byte, bool)

type prismAgentBinding struct {
	address  *net.UDPAddr
	lastSeen time.Time
}

type prismMobileRoute struct {
	address  *net.UDPAddr
	owner    [16]byte
	lastSeen time.Time
}

type prismRouteKey struct {
	installationID [16]byte
	route          [8]byte
}

type PrismRelay struct {
	secrets PrismSecretLookup

	mu       sync.RWMutex
	agents   map[[16]byte]prismAgentBinding
	routes   map[prismRouteKey]prismMobileRoute
	replayed map[[32]byte]time.Time
}

func NewPrismRelay(secrets PrismSecretLookup) (*PrismRelay, error) {
	if secrets == nil {
		return nil, errors.New("PrismLink relay requires a secret lookup")
	}
	return &PrismRelay{
		secrets: secrets,
		agents:  make(map[[16]byte]prismAgentBinding), routes: make(map[prismRouteKey]prismMobileRoute), replayed: make(map[[32]byte]time.Time),
	}, nil
}

func (relay *PrismRelay) Serve(agentConn, mobileConn *net.UDPConn) error {
	if agentConn == nil || mobileConn == nil {
		return errors.New("PrismLink relay requires agent and mobile UDP sockets")
	}
	errors := make(chan error, 2)
	go func() { errors <- relay.serveAgents(agentConn, mobileConn) }()
	go func() { errors <- relay.serveMobile(agentConn, mobileConn) }()
	return <-errors
}

func (relay *PrismRelay) serveAgents(agentConn, mobileConn *net.UDPConn) error {
	buffer := make([]byte, prismlink.RelayHeaderSize+prismlink.MaxDatagram+64)
	for {
		n, source, err := agentConn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		packet := append([]byte(nil), buffer[:n]...)
		message, err := prismlink.ParseRelayDatagram(packet)
		if err != nil {
			continue
		}
		now := time.Now()
		if message.Type == prismlink.RelayRegister {
			secret, ok := relay.secrets(message.InstallationID)
			digest := sha256.Sum256(packet)
			relay.mu.Lock()
			_, replayed := relay.replayed[digest]
			if ok && !replayed && prismlink.VerifyRelayRegistration(packet, secret, now) == nil {
				relay.agents[message.InstallationID] = prismAgentBinding{address: cloneUDPAddress(source), lastSeen: now}
				relay.replayed[digest] = now.Add(prismlink.RelayAuthWindow)
			}
			relay.expireLocked(now)
			relay.mu.Unlock()
			continue
		}
		if message.Type != prismlink.RelayFromAgent {
			continue
		}
		key := prismRouteKey{installationID: message.InstallationID, route: message.Route}
		relay.mu.RLock()
		agent := relay.agents[message.InstallationID]
		route := relay.routes[key]
		relay.mu.RUnlock()
		if agent.address == nil || route.address == nil || !agent.address.IP.Equal(source.IP) || agent.address.Port != source.Port || now.Sub(route.lastSeen) > prismRelayIdleTimeout {
			continue
		}
		_, _ = mobileConn.WriteToUDP(message.Payload, route.address)
	}
}

func (relay *PrismRelay) serveMobile(agentConn, mobileConn *net.UDPConn) error {
	buffer := make([]byte, prismlink.RelayHeaderSize+prismlink.MaxDatagram)
	for {
		n, source, err := mobileConn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		message, err := prismlink.ParseRelayDatagram(buffer[:n])
		if err != nil {
			continue
		}
		now := time.Now()
		key := prismRouteKey{installationID: message.InstallationID, route: message.Route}
		switch message.Type {
		case prismlink.RelayMobileBind:
			relay.bindMobileRoute(key, buffer[:n], source, now)
		case prismlink.RelayMobileData:
			// Route identifiers travel in clear text. Only an authenticated
			// binding may set the delivery address; data from any other
			// source is dropped, so an observer can neither redirect a
			// phone's traffic nor exhaust the agent's route table.
			relay.mu.Lock()
			agent := relay.agents[message.InstallationID]
			route, bound := relay.routes[key]
			fresh := bound && route.address.IP.Equal(source.IP) && route.address.Port == source.Port &&
				agent.address != nil && now.Sub(agent.lastSeen) <= prismRelayIdleTimeout
			if fresh {
				route.lastSeen = now
				relay.routes[key] = route
			}
			relay.mu.Unlock()
			if !fresh {
				continue
			}
			forward, err := prismlink.EncodeRelayData(prismlink.RelayToAgent, message.InstallationID, message.Route, message.Payload)
			if err == nil {
				_, _ = agentConn.WriteToUDP(forward, agent.address)
			}
		}
	}
}

func (relay *PrismRelay) bindMobileRoute(key prismRouteKey, packet []byte, source *net.UDPAddr, now time.Time) {
	secret, ok := relay.secrets(key.installationID)
	if !ok {
		return
	}
	digest := sha256.Sum256(packet)
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if _, replayed := relay.replayed[digest]; replayed {
		return
	}
	owner, err := prismlink.VerifyRelayMobileBind(packet, secret, now)
	if err != nil {
		return
	}
	relay.replayed[digest] = now.Add(prismlink.RelayAuthWindow)
	relay.expireLocked(now)
	existing, bound := relay.routes[key]
	if bound && existing.owner != owner {
		return
	}
	if !bound && len(relay.routes) >= prismRelayMaxRoutes {
		return
	}
	relay.routes[key] = prismMobileRoute{address: cloneUDPAddress(source), owner: owner, lastSeen: now}
}

func (relay *PrismRelay) expireLocked(now time.Time) {
	for id, agent := range relay.agents {
		if now.Sub(agent.lastSeen) > prismRelayIdleTimeout {
			delete(relay.agents, id)
		}
	}
	for key, route := range relay.routes {
		if now.Sub(route.lastSeen) > prismRelayIdleTimeout {
			delete(relay.routes, key)
		}
	}
	for digest, expires := range relay.replayed {
		if now.After(expires) {
			delete(relay.replayed, digest)
		}
	}
}

type PrismAgent struct {
	RelayAddress   string
	LocalAddress   string
	InstallationID [16]byte
	Secret         [32]byte

	mu               sync.Mutex
	routes           map[[8]byte]*prismAgentRoute
	relay            atomic.Pointer[net.UDPAddr]
	registerInterval time.Duration
}

type prismAgentRoute struct {
	conn     *net.UDPConn
	lastSeen time.Time
}

func (agent *PrismAgent) Run(ctx context.Context) error {
	if agent.InstallationID == [16]byte{} || agent.Secret == [32]byte{} || !isLoopbackTarget(agent.LocalAddress) {
		return errors.New("invalid PrismLink agent configuration")
	}
	relay, err := resolvePrismRelay("udp", agent.RelayAddress)
	if err != nil {
		return err
	}
	agent.relay.Store(relay)
	localServer, err := net.ResolveUDPAddr("udp", agent.LocalAddress)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)
	agent.routes = make(map[[8]byte]*prismAgentRoute)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	register := func() error {
		// Follow a changed relay address (new VPS, new IP behind the same
		// name). A failed lookup keeps the last working address.
		if current, err := resolvePrismRelay("udp", agent.RelayAddress); err == nil {
			agent.relay.Store(current)
		}
		packet, err := prismlink.EncodeRelayRegistration(agent.InstallationID, agent.Secret, time.Now())
		if err == nil {
			_, err = conn.WriteToUDP(packet, agent.relay.Load())
		}
		return err
	}
	if err := register(); err != nil {
		return err
	}
	interval := agent.registerInterval
	if interval <= 0 {
		interval = prismAgentRegisterInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = register()
				agent.cleanupRoutes()
			}
		}
	}()
	buffer := make([]byte, prismlink.RelayHeaderSize+prismlink.MaxDatagram)
	for {
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		relay := agent.relay.Load()
		if !source.IP.Equal(relay.IP) || source.Port != relay.Port {
			continue
		}
		message, err := prismlink.ParseRelayDatagram(buffer[:n])
		if err != nil || message.Type != prismlink.RelayToAgent || message.InstallationID != agent.InstallationID {
			continue
		}
		route, err := agent.route(ctx, conn, localServer, message.Route)
		if err == nil {
			_, _ = route.conn.Write(message.Payload)
		}
	}
}

func (agent *PrismAgent) route(ctx context.Context, relayConn *net.UDPConn, localServer *net.UDPAddr, token [8]byte) (*prismAgentRoute, error) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if route := agent.routes[token]; route != nil {
		route.lastSeen = time.Now()
		return route, nil
	}
	if len(agent.routes) >= prismAgentMaxRoutes {
		return nil, errors.New("PrismLink agent route limit reached")
	}
	conn, err := net.DialUDP("udp", nil, localServer)
	if err != nil {
		return nil, err
	}
	route := &prismAgentRoute{conn: conn, lastSeen: time.Now()}
	agent.routes[token] = route
	go agent.readLocalRoute(ctx, relayConn, token, route)
	return route, nil
}

func (agent *PrismAgent) readLocalRoute(ctx context.Context, relayConn *net.UDPConn, token [8]byte, route *prismAgentRoute) {
	buffer := make([]byte, prismlink.MaxDatagram)
	for {
		_ = route.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := route.conn.Read(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() && ctx.Err() == nil {
				continue
			}
			return
		}
		packet, err := prismlink.EncodeRelayData(prismlink.RelayFromAgent, agent.InstallationID, token, buffer[:n])
		if err == nil {
			_, _ = relayConn.WriteToUDP(packet, agent.relay.Load())
		}
	}
}

func (agent *PrismAgent) cleanupRoutes() {
	now := time.Now()
	agent.mu.Lock()
	for token, route := range agent.routes {
		if now.Sub(route.lastSeen) > prismRelayIdleTimeout {
			_ = route.conn.Close()
			delete(agent.routes, token)
		}
	}
	agent.mu.Unlock()
}

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func PrismInstallationID(encoded string) ([16]byte, error) {
	var id [16]byte
	if len(encoded) != 32 {
		return id, errors.New("invalid PrismLink installation id")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(id) {
		return id, errors.New("invalid PrismLink installation id")
	}
	copy(id[:], decoded)
	return id, nil
}
