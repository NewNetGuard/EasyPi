package mobilelink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const maxClientHello = 64 * 1024

// ReadClientHelloSNI reads and preserves the initial TLS records without
// terminating TLS. The returned bytes must be forwarded unchanged to EasyPi.
func ReadClientHelloSNI(conn net.Conn, timeout time.Duration) (string, []byte, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	var raw, handshake []byte
	for len(raw) < maxClientHello {
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return "", raw, err
		}
		if header[0] != 22 {
			return "", raw, errors.New("mobile link ingress did not begin with a TLS handshake")
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if size <= 0 || len(raw)+5+size > maxClientHello {
			return "", raw, errors.New("TLS ClientHello exceeds the mobile link limit")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return "", raw, err
		}
		raw = append(raw, header[:]...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) >= 4 {
			if handshake[0] != 1 {
				return "", raw, errors.New("first TLS handshake message is not ClientHello")
			}
			length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if length+4 <= len(handshake) {
				name, err := parseClientHelloSNI(handshake[4 : 4+length])
				return name, raw, err
			}
		}
	}
	return "", raw, errors.New("incomplete TLS ClientHello")
}

func parseClientHelloSNI(body []byte) (string, error) {
	offset := 2 + 32
	if len(body) < offset+1 {
		return "", errors.New("truncated TLS ClientHello")
	}
	offset += 1 + int(body[offset])
	if len(body) < offset+2 {
		return "", errors.New("truncated TLS cipher suites")
	}
	offset += 2 + int(binary.BigEndian.Uint16(body[offset:offset+2]))
	if len(body) < offset+1 {
		return "", errors.New("truncated TLS compression methods")
	}
	offset += 1 + int(body[offset])
	if len(body) < offset+2 {
		return "", errors.New("TLS ClientHello has no extensions")
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if extensionsLength > len(body)-offset {
		return "", errors.New("truncated TLS extensions")
	}
	end := offset + extensionsLength
	for offset+4 <= end {
		typ := binary.BigEndian.Uint16(body[offset : offset+2])
		length := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if length > end-offset {
			return "", errors.New("truncated TLS extension")
		}
		if typ == 0 {
			return parseServerNameExtension(body[offset : offset+length])
		}
		offset += length
	}
	return "", errors.New("TLS ClientHello does not contain SNI")
}

func parseServerNameExtension(extension []byte) (string, error) {
	if len(extension) < 2 {
		return "", errors.New("truncated TLS server name extension")
	}
	length := int(binary.BigEndian.Uint16(extension[:2]))
	if length != len(extension)-2 {
		return "", errors.New("invalid TLS server name list")
	}
	offset := 2
	for offset+3 <= len(extension) {
		typ := extension[offset]
		nameLength := int(binary.BigEndian.Uint16(extension[offset+1 : offset+3]))
		offset += 3
		if nameLength > len(extension)-offset {
			return "", errors.New("truncated TLS server name")
		}
		if typ == 0 {
			name := strings.ToLower(string(extension[offset : offset+nameLength]))
			if name == "" || strings.ContainsAny(name, "\x00/\\") {
				return "", errors.New("invalid TLS server name")
			}
			return name, nil
		}
		offset += nameLength
	}
	return "", fmt.Errorf("TLS server name extension has no host name")
}
