package main

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"chameleon/shared"
)

var kernelTunnelStopping atomic.Bool

func startRelayReader(session *clientSession, relay *udpRelay) {
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-relay.done:
				return
			default:
			}

			_ = relay.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := relay.conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				logOperationalFailure("relay", "read failed", err)
				return
			}

			session.mu.Lock()
			clientIP := cloneIPv4(session.clientIP)
			clientPort := session.clientPort
			session.mu.Unlock()
			if clientIP == nil || clientPort == 0 {
				continue
			}

			rawPacket, err := shared.BuildIPv4UDPPacket(
				relay.upstream.IP,
				clientIP,
				uint16(relay.upstream.Port),
				clientPort,
				buf[:n],
			)
			if err != nil {
				logOperationalFailure("relay", "response packet build failed", err)
				continue
			}

			payload := rawPacket

			select {
			case session.outbox <- payload:
			default:
				logRateLimitedEvent("relay", "response dropped because queue is full")
			}
			enqueueDoHFallback(session, payload)
		}
	}()
}

func ensureSessionRelay(session *clientSession, upstreamIP net.IP, upstreamPort uint16) (*udpRelay, error) {
	upstream4 := cloneIPv4(upstreamIP)
	if upstream4 == nil {
		return nil, fmt.Errorf("unsupported upstream IP version")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.relay != nil &&
		session.relay.upstream.Port == int(upstreamPort) &&
		session.relay.upstream.IP.Equal(upstream4) {
		return session.relay, nil
	}

	if session.relay != nil {
		session.relay.close()
		session.relay = nil
	}

	upstream := &net.UDPAddr{IP: upstream4, Port: int(upstreamPort)}
	conn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return nil, fmt.Errorf("dial upstream failed: %w", err)
	}
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)

	relay := &udpRelay{
		conn:     conn,
		upstream: upstream,
		done:     make(chan struct{}),
	}
	session.relay = relay
	startRelayReader(session, relay)

	return relay, nil
}

func startKernelTunnelReader(tun *kernelTunnel) {
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := tun.ReadPacket(buf)
			if err != nil {
				if kernelTunnelStopping.Load() {
					return
				}
				logOperationalFailure("tun", "read loop stopped", err)
				return
			}
			if n <= 0 {
				continue
			}

			packet := append([]byte(nil), buf[:n]...)
			_, dstIP, err := parseIPv4SrcDst(packet)
			if err != nil {
				continue
			}
			if prismLink != nil && prismLink.deliver(packet, dstIP) {
				continue
			}

			session := sessionForClientIP(dstIP)
			if session == nil {
				continue
			}

			payload := packet

			select {
			case session.outbox <- payload:
			default:
				logRateLimitedEvent("tun", "downlink packet dropped because queue is full")
			}
			enqueueDoHFallback(session, payload)
		}
	}()
}

func forwardClientPacketToVPN(session *clientSession, rawPacket []byte) error {
	normalized, err := trimIPv4Packet(rawPacket)
	if err != nil {
		return err
	}
	rawPacket = normalized

	srcIP, _, err := parseIPv4SrcDst(rawPacket)
	if err != nil {
		return err
	}
	// Keep mapping so packets coming back from kernel TUN can be routed
	// to the right client session.
	session.cryptoMu.RLock()
	allowed := append(net.IP(nil), session.allowedIP...)
	session.cryptoMu.RUnlock()
	if allowed == nil || !allowed.Equal(srcIP) {
		return errPacketSourceNotAssigned
	}
	if !setSessionClientIP(session, srcIP, 0) {
		return fmt.Errorf("client address already owned")
	}

	if kernelTun != nil {
		if err := kernelTun.WritePacket(rawPacket); err != nil {
			return fmt.Errorf("kernel tunnel write failed: %w", err)
		}
		return nil
	}

	// Legacy UDP-only fallback (used if kernel tunnel couldn't start).
	pkt, err := shared.ParseIPv4UDPPacket(rawPacket)
	if err != nil {
		return err
	}
	setSessionClientIP(session, pkt.SrcIP, pkt.SrcPort)

	relay, err := ensureSessionRelay(session, pkt.DstIP, pkt.DstPort)
	if err != nil {
		return err
	}

	if _, err := relay.conn.Write(pkt.Payload); err != nil {
		return fmt.Errorf("upstream write failed: %w", err)
	}

	return nil
}
