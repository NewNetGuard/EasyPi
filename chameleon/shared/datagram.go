//go:build quicdatagram
// +build quicdatagram

package shared

import (
	"encoding/binary"
	"fmt"
)

const (
	QUICDatagramALPN        = "chameleon-dgram"
	DefaultQUICDatagramPort = 8444

	DatagramFrameVersion = 1

	DatagramFrameTypeAuth = 1
	DatagramFrameTypeData = 2
	DatagramFrameTypePing = 3
)

// EncodeDatagramFrame wraps payload in a compact binary envelope:
// [1 byte version][1 byte type][2 bytes payload_len][payload].
func EncodeDatagramFrame(frameType byte, payload []byte) ([]byte, error) {
	if len(payload) > 0xFFFF {
		return nil, fmt.Errorf("datagram payload too large: %d", len(payload))
	}
	out := make([]byte, 4+len(payload))
	out[0] = DatagramFrameVersion
	out[1] = frameType
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// DecodeDatagramFrame unwraps [version][type][len][payload].
func DecodeDatagramFrame(raw []byte) (frameType byte, payload []byte, err error) {
	if len(raw) < 4 {
		return 0, nil, fmt.Errorf("short datagram frame")
	}
	if raw[0] != DatagramFrameVersion {
		return 0, nil, fmt.Errorf("unsupported datagram frame version %d", raw[0])
	}
	n := int(binary.BigEndian.Uint16(raw[2:4]))
	if len(raw)-4 != n {
		return 0, nil, fmt.Errorf("datagram frame length mismatch: hdr=%d body=%d", n, len(raw)-4)
	}
	return raw[1], raw[4:], nil
}
