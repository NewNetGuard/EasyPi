// Package prismlink implements the EasyPi IP-over-UDP data plane.
//
// PrismLink deliberately provides authenticated, encrypted, unordered packet
// delivery. Inner TCP and QUIC remain responsible for retransmission; the
// outer transport never creates TCP-over-TCP head-of-line blocking.
package prismlink

import (
	"encoding/binary"
	"errors"
)

const (
	Version        = 1
	HeaderSize     = 24
	MaxInnerPacket = 1200
	MaxDatagram    = HeaderSize + MaxInnerPacket + 16
	HandshakeTTL   = 90
)

type PacketType uint8

const (
	PacketClientHello PacketType = 1
	PacketServerHello PacketType = 2
	PacketData        PacketType = 3
	PacketPing        PacketType = 4
	PacketPong        PacketType = 5
	PacketAck         PacketType = 6
)

var magic = [4]byte{'E', 'P', 'L', '2'}

type header struct {
	typ       PacketType
	flags     uint16
	sessionID uint64
	sequence  uint64
}

func encodeHeader(target []byte, value header) error {
	if len(target) < HeaderSize {
		return errors.New("PrismLink header buffer is too small")
	}
	copy(target[:4], magic[:])
	target[4] = Version
	target[5] = byte(value.typ)
	binary.BigEndian.PutUint16(target[6:8], value.flags)
	binary.BigEndian.PutUint64(target[8:16], value.sessionID)
	binary.BigEndian.PutUint64(target[16:24], value.sequence)
	return nil
}

func decodeHeader(packet []byte) (header, error) {
	if len(packet) < HeaderSize || string(packet[:4]) != string(magic[:]) || packet[4] != Version {
		return header{}, errors.New("invalid PrismLink packet header")
	}
	typ := PacketType(packet[5])
	if typ < PacketClientHello || typ > PacketAck {
		return header{}, errors.New("invalid PrismLink packet type")
	}
	return header{
		typ:       typ,
		flags:     binary.BigEndian.Uint16(packet[6:8]),
		sessionID: binary.BigEndian.Uint64(packet[8:16]),
		sequence:  binary.BigEndian.Uint64(packet[16:24]),
	}, nil
}

// SessionID returns the clear routing identifier without authenticating the
// datagram. Relays may use it only as an opaque lookup key; endpoints must call
// Session.Open before trusting any packet.
func SessionID(packet []byte) (uint64, bool) {
	header, err := decodeHeader(packet)
	return header.sessionID, err == nil && header.sessionID != 0
}

// IsPacket reports whether a datagram has the PrismLink wire prefix. It does
// not authenticate the packet.
func IsPacket(packet []byte) bool {
	_, err := decodeHeader(packet)
	return err == nil
}
