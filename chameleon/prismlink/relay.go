package prismlink

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	RelayHeaderSize = 32
	RelayAuthWindow = 90 * time.Second
)

type RelayType uint8

const (
	RelayRegister       RelayType = 1
	RelayMobileData     RelayType = 2
	RelayToAgent        RelayType = 3
	RelayFromAgent      RelayType = 4
	RelayMobileBind     RelayType = 5
	relayRegisterSize             = RelayHeaderSize + 8 + 16 + sha256.Size
	relayMobileBindSize           = RelayHeaderSize + 16 + 8 + 16 + sha256.Size
)

var relayMagic = [4]byte{'E', 'P', 'L', 'R'}

type RelayDatagram struct {
	Type           RelayType
	InstallationID [16]byte
	Route          [8]byte
	Payload        []byte
}

func EncodeRelayData(typ RelayType, installationID [16]byte, route [8]byte, payload []byte) ([]byte, error) {
	if typ != RelayMobileData && typ != RelayToAgent && typ != RelayFromAgent {
		return nil, errors.New("invalid PrismLink relay data type")
	}
	if installationID == [16]byte{} || route == [8]byte{} || !IsPacket(payload) || len(payload) > MaxDatagram {
		return nil, errors.New("invalid PrismLink relay data")
	}
	packet := make([]byte, RelayHeaderSize+len(payload))
	encodeRelayHeader(packet, typ, installationID, route)
	copy(packet[RelayHeaderSize:], payload)
	return packet, nil
}

func EncodeRelayRegistration(installationID [16]byte, secret [32]byte, now time.Time) ([]byte, error) {
	if installationID == [16]byte{} || secret == [32]byte{} {
		return nil, errors.New("invalid PrismLink relay identity")
	}
	packet := make([]byte, relayRegisterSize)
	encodeRelayHeader(packet, RelayRegister, installationID, [8]byte{})
	binary.BigEndian.PutUint64(packet[RelayHeaderSize:RelayHeaderSize+8], uint64(now.Unix()))
	if _, err := rand.Read(packet[RelayHeaderSize+8 : RelayHeaderSize+24]); err != nil {
		return nil, err
	}
	copy(packet[RelayHeaderSize+24:], relayMAC(secret[:], packet[:RelayHeaderSize+24]))
	return packet, nil
}

func ParseRelayDatagram(packet []byte) (RelayDatagram, error) {
	if len(packet) < RelayHeaderSize || string(packet[:4]) != string(relayMagic[:]) || packet[4] != Version || packet[6] != 0 || packet[7] != 0 {
		return RelayDatagram{}, errors.New("invalid PrismLink relay header")
	}
	result := RelayDatagram{Type: RelayType(packet[5])}
	copy(result.InstallationID[:], packet[8:24])
	copy(result.Route[:], packet[24:32])
	if result.InstallationID == [16]byte{} {
		return RelayDatagram{}, errors.New("invalid PrismLink relay identity")
	}
	switch result.Type {
	case RelayRegister:
		if len(packet) != relayRegisterSize || result.Route != [8]byte{} {
			return RelayDatagram{}, errors.New("invalid PrismLink relay registration")
		}
	case RelayMobileBind:
		if len(packet) != relayMobileBindSize || result.Route == [8]byte{} {
			return RelayDatagram{}, errors.New("invalid PrismLink mobile route binding")
		}
	case RelayMobileData, RelayToAgent, RelayFromAgent:
		if result.Route == [8]byte{} || len(packet) <= RelayHeaderSize || len(packet) > RelayHeaderSize+MaxDatagram || !IsPacket(packet[RelayHeaderSize:]) {
			return RelayDatagram{}, errors.New("invalid PrismLink relayed packet")
		}
		result.Payload = packet[RelayHeaderSize:]
	default:
		return RelayDatagram{}, errors.New("invalid PrismLink relay type")
	}
	return result, nil
}

func VerifyRelayRegistration(packet []byte, secret [32]byte, now time.Time) error {
	message, err := ParseRelayDatagram(packet)
	if err != nil || message.Type != RelayRegister || secret == [32]byte{} {
		return errors.New("invalid PrismLink relay registration")
	}
	timestamp := int64(binary.BigEndian.Uint64(packet[RelayHeaderSize : RelayHeaderSize+8]))
	if delta := now.Sub(time.Unix(timestamp, 0)); delta < -RelayAuthWindow || delta > RelayAuthWindow {
		return errors.New("PrismLink relay registration is outside the authentication window")
	}
	expected := relayMAC(secret[:], packet[:RelayHeaderSize+24])
	if !hmac.Equal(expected, packet[RelayHeaderSize+24:]) {
		return errors.New("invalid PrismLink relay registration authenticator")
	}
	return nil
}

// MobileRouteKey derives the per-phone key that authorises relay route
// bindings. The relay and the home EasyPi derive it from the installation
// secret; a phone receives only its own key and therefore can neither forge an
// agent registration nor bind another phone's route.
func MobileRouteKey(installationSecret [32]byte, clientID [16]byte) [32]byte {
	mac := hmac.New(sha256.New, installationSecret[:])
	_, _ = mac.Write([]byte("easypi/prismlink/mobile-route-key/v1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(clientID[:])
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return key
}

// EncodeRelayMobileBind authorises the relay to deliver one route to the
// sender's current address.
func EncodeRelayMobileBind(installationID [16]byte, route [8]byte, clientID [16]byte, routeKey [32]byte, now time.Time) ([]byte, error) {
	if installationID == [16]byte{} || route == [8]byte{} || clientID == [16]byte{} || routeKey == [32]byte{} {
		return nil, errors.New("invalid PrismLink mobile route binding")
	}
	packet := make([]byte, relayMobileBindSize)
	encodeRelayHeader(packet, RelayMobileBind, installationID, route)
	body := packet[RelayHeaderSize:]
	copy(body[:16], clientID[:])
	binary.BigEndian.PutUint64(body[16:24], uint64(now.Unix()))
	if _, err := rand.Read(body[24:40]); err != nil {
		return nil, err
	}
	copy(body[40:], mobileBindMAC(routeKey, packet[:RelayHeaderSize+40]))
	return packet, nil
}

// VerifyRelayMobileBind authenticates a route binding and returns the phone
// identity that owns the route.
func VerifyRelayMobileBind(packet []byte, installationSecret [32]byte, now time.Time) ([16]byte, error) {
	var clientID [16]byte
	message, err := ParseRelayDatagram(packet)
	if err != nil || message.Type != RelayMobileBind || installationSecret == [32]byte{} {
		return clientID, errors.New("invalid PrismLink mobile route binding")
	}
	body := packet[RelayHeaderSize:]
	copy(clientID[:], body[:16])
	if clientID == [16]byte{} {
		return clientID, errors.New("invalid PrismLink mobile route binding")
	}
	timestamp := int64(binary.BigEndian.Uint64(body[16:24]))
	if delta := now.Sub(time.Unix(timestamp, 0)); delta < -RelayAuthWindow || delta > RelayAuthWindow {
		return clientID, errors.New("PrismLink mobile route binding is outside the authentication window")
	}
	expected := mobileBindMAC(MobileRouteKey(installationSecret, clientID), packet[:RelayHeaderSize+40])
	if !hmac.Equal(expected, body[40:]) {
		return clientID, errors.New("invalid PrismLink mobile route binding authenticator")
	}
	return clientID, nil
}

func mobileBindMAC(routeKey [32]byte, payload []byte) []byte {
	mac := hmac.New(sha256.New, routeKey[:])
	_, _ = mac.Write([]byte("easypi/prismlink/mobile-bind/v1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func encodeRelayHeader(packet []byte, typ RelayType, installationID [16]byte, route [8]byte) {
	copy(packet[:4], relayMagic[:])
	packet[4] = Version
	packet[5] = byte(typ)
	copy(packet[8:24], installationID[:])
	copy(packet[24:32], route[:])
}

func relayMAC(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("easypi/prismlink/relay-register/v1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
