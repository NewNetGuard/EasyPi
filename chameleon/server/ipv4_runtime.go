package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

var errNotIPv4 = errors.New("not ipv4")

// errPacketSourceNotAssigned marks an authenticated, decrypted packet whose
// IPv4 source is not the address assigned to the device. The packet is never
// forwarded; callers drop it and keep the carrier, because one stray packet
// (for example from a flow the client's NAT forgot) must not stall the tunnel.
var errPacketSourceNotAssigned = errors.New("packet source is not assigned to authenticated device")

func cloneIPv4(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return append(net.IP(nil), ip4...)
}

func ipKey(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return ip4.String()
}

func unregisterClientIP(session *clientSession, ip net.IP) {
	key := ipKey(ip)
	if key == "" {
		return
	}
	ipToSessMu.Lock()
	if current, ok := ipToSess[key]; ok && current == session {
		delete(ipToSess, key)
	}
	ipToSessMu.Unlock()
}

func setSessionClientIP(session *clientSession, ip net.IP, srcPort uint16) bool {
	ip4 := cloneIPv4(ip)
	if ip4 == nil {
		return false
	}
	// Address ownership is checked while holding the mapping lock. Never let
	// another authenticated principal replace an existing owner.
	ipToSessMu.Lock()
	defer ipToSessMu.Unlock()
	if current := ipToSess[ipKey(ip4)]; current != nil && current != session {
		current.cryptoMu.RLock()
		oldPrincipal := current.credentialID
		current.cryptoMu.RUnlock()
		session.cryptoMu.RLock()
		newPrincipal := session.credentialID
		session.cryptoMu.RUnlock()
		if oldPrincipal == "" || oldPrincipal != newPrincipal {
			return false
		}
	}
	var oldIP net.IP

	session.mu.Lock()
	oldIP = cloneIPv4(session.clientIP)
	session.clientIP = ip4
	session.clientPort = srcPort
	session.mu.Unlock()

	oldKey := ipKey(oldIP)
	newKey := ipKey(ip4)

	if oldKey != "" && oldKey != newKey {
		if current, ok := ipToSess[oldKey]; ok && current == session {
			delete(ipToSess, oldKey)
		}
	}
	if newKey != "" {
		ipToSess[newKey] = session
	}
	return true
}

func sessionForClientIP(ip net.IP) *clientSession {
	key := ipKey(ip)
	if key == "" {
		return nil
	}
	ipToSessMu.RLock()
	s := ipToSess[key]
	ipToSessMu.RUnlock()
	return s
}

func parseIPv4SrcDst(raw []byte) (net.IP, net.IP, error) {
	if len(raw) < 20 {
		return nil, nil, fmt.Errorf("packet too small")
	}
	if raw[0]>>4 != 4 {
		return nil, nil, errNotIPv4
	}

	ihl := int(raw[0]&0x0F) * 4
	if ihl < 20 || len(raw) < ihl {
		return nil, nil, fmt.Errorf("malformed ipv4 header")
	}

	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen < ihl || totalLen > len(raw) {
		return nil, nil, fmt.Errorf("malformed ipv4 total length")
	}

	src := net.IPv4(raw[12], raw[13], raw[14], raw[15])
	dst := net.IPv4(raw[16], raw[17], raw[18], raw[19])
	return src, dst, nil
}

func trimIPv4Packet(raw []byte) ([]byte, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("packet too small")
	}
	if raw[0]>>4 != 4 {
		return nil, errNotIPv4
	}

	ihl := int(raw[0]&0x0F) * 4
	if ihl < 20 || len(raw) < ihl {
		return nil, fmt.Errorf("malformed ipv4 header")
	}

	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen < ihl || totalLen > len(raw) {
		return nil, fmt.Errorf("malformed ipv4 total length")
	}

	return raw[:totalLen], nil
}

func isLikelyRawIPv4Packet(raw []byte) bool {
	_, err := trimIPv4Packet(raw)
	return err == nil
}
