package shared

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

var (
	ErrUnsupportedIPVersion = errors.New("unsupported IP version")
	ErrNotUDPPacket         = errors.New("packet is not UDP")
	ErrMalformedPacket      = errors.New("malformed packet")
)

// IPv4UDPPacket is a parsed IPv4+UDP packet payload.
type IPv4UDPPacket struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// ParseIPv4UDPPacket parses a raw IPv4 UDP packet.
func ParseIPv4UDPPacket(raw []byte) (IPv4UDPPacket, error) {
	if len(raw) < 20 {
		return IPv4UDPPacket{}, fmt.Errorf("%w: IPv4 header too short", ErrMalformedPacket)
	}

	version := raw[0] >> 4
	if version != 4 {
		return IPv4UDPPacket{}, fmt.Errorf("%w: got %d", ErrUnsupportedIPVersion, version)
	}

	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || len(raw) < ihl+8 {
		return IPv4UDPPacket{}, fmt.Errorf("%w: invalid IPv4 IHL", ErrMalformedPacket)
	}

	if raw[9] != 17 {
		return IPv4UDPPacket{}, ErrNotUDPPacket
	}

	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen == 0 || totalLen > len(raw) {
		totalLen = len(raw)
	}
	if totalLen < ihl+8 {
		return IPv4UDPPacket{}, fmt.Errorf("%w: truncated UDP header", ErrMalformedPacket)
	}

	udp := raw[ihl:totalLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return IPv4UDPPacket{}, fmt.Errorf("%w: invalid UDP length", ErrMalformedPacket)
	}

	srcIP := append(net.IP(nil), raw[12:16]...)
	dstIP := append(net.IP(nil), raw[16:20]...)
	payload := make([]byte, udpLen-8)
	copy(payload, udp[8:udpLen])

	return IPv4UDPPacket{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: binary.BigEndian.Uint16(udp[0:2]),
		DstPort: binary.BigEndian.Uint16(udp[2:4]),
		Payload: payload,
	}, nil
}

// BuildIPv4UDPPacket builds a raw IPv4 UDP packet from fields.
func BuildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("%w: only IPv4 is supported", ErrUnsupportedIPVersion)
	}

	totalLen := 20 + 8 + len(payload)
	if totalLen > 65535 {
		return nil, fmt.Errorf("%w: packet too large (%d bytes)", ErrMalformedPacket, totalLen)
	}

	raw := make([]byte, totalLen)

	// IPv4 header
	raw[0] = 0x45 // version=4, IHL=5
	raw[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(raw[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(raw[4:6], 0)
	binary.BigEndian.PutUint16(raw[6:8], 0)
	raw[8] = 64 // TTL
	raw[9] = 17 // UDP
	copy(raw[12:16], src4)
	copy(raw[16:20], dst4)
	ipChecksum := internetChecksum(raw[:20])
	binary.BigEndian.PutUint16(raw[10:12], ipChecksum)

	// UDP header + payload
	udpOffset := 20
	udpLen := 8 + len(payload)
	binary.BigEndian.PutUint16(raw[udpOffset:udpOffset+2], srcPort)
	binary.BigEndian.PutUint16(raw[udpOffset+2:udpOffset+4], dstPort)
	binary.BigEndian.PutUint16(raw[udpOffset+4:udpOffset+6], uint16(udpLen))
	copy(raw[udpOffset+8:], payload)

	udpChecksum := udpChecksumIPv4(src4, dst4, raw[udpOffset:])
	if udpChecksum == 0 {
		// RFC 768: checksum value 0 is transmitted as all ones.
		udpChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(raw[udpOffset+6:udpOffset+8], udpChecksum)

	return raw, nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksumIPv4(src4, dst4 []byte, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src4)
	copy(pseudo[4:8], dst4)
	pseudo[8] = 0
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return internetChecksum(pseudo)
}
