package mobilelink

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	MaxControlFrame = 8 * 1024
	AuthWindow      = 90 * time.Second
	identityContext = "easypi-mobile-link-installation-v1"
)

type Message struct {
	Type           string `json:"type"`
	InstallationID string `json:"installation_id"`
	ConnectionID   string `json:"connection_id,omitempty"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
	MAC            string `json:"mac"`
}

func InstallationID(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(identityContext))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func Sign(secret []byte, message *Message, now time.Time) error {
	if len(secret) != 32 {
		return errors.New("mobile link secret must contain 32 bytes")
	}
	if err := validateMessageIdentity(message); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate authentication nonce: %w", err)
	}
	message.Timestamp = now.Unix()
	message.Nonce = hex.EncodeToString(nonce)
	message.MAC = hex.EncodeToString(messageMAC(secret, *message))
	return nil
}

func Verify(secret []byte, message Message, now time.Time) error {
	if len(secret) != 32 {
		return errors.New("mobile link secret must contain 32 bytes")
	}
	if err := validateMessageIdentity(&message); err != nil {
		return err
	}
	if delta := now.Sub(time.Unix(message.Timestamp, 0)); delta < -AuthWindow || delta > AuthWindow {
		return errors.New("mobile link authentication timestamp is outside the allowed window")
	}
	nonce, err := hex.DecodeString(message.Nonce)
	if err != nil || len(nonce) != 16 {
		return errors.New("invalid mobile link authentication nonce")
	}
	provided, err := hex.DecodeString(message.MAC)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("invalid mobile link authenticator")
	}
	if !hmac.Equal(provided, messageMAC(secret, message)) {
		return errors.New("mobile link authentication failed")
	}
	return nil
}

func WriteMessage(writer io.Writer, message Message) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode mobile link control message: %w", err)
	}
	if len(payload) == 0 || len(payload) > MaxControlFrame {
		return errors.New("mobile link control message exceeds the size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err = writer.Write(payload)
	return err
}

func ReadMessage(reader io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxControlFrame {
		return Message{}, errors.New("invalid mobile link control frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Message{}, err
	}
	var message Message
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return Message{}, fmt.Errorf("decode mobile link control message: %w", err)
	}
	return message, nil
}

func validateMessageIdentity(message *Message) error {
	if message.Type != "register" && message.Type != "open" && message.Type != "data" && message.Type != "ready" && message.Type != "ping" && message.Type != "pong" {
		return errors.New("invalid mobile link control message type")
	}
	if len(message.InstallationID) != 32 {
		return errors.New("invalid mobile link installation id")
	}
	if _, err := hex.DecodeString(message.InstallationID); err != nil {
		return errors.New("invalid mobile link installation id")
	}
	if (message.Type == "open" || message.Type == "data" || message.Type == "ready") && len(message.ConnectionID) != 32 {
		return errors.New("invalid mobile link connection id")
	}
	if message.ConnectionID != "" {
		if _, err := hex.DecodeString(message.ConnectionID); err != nil {
			return errors.New("invalid mobile link connection id")
		}
	}
	return nil
}

func messageMAC(secret []byte, message Message) []byte {
	mac := hmac.New(sha256.New, secret)
	parts := []string{
		"easypi-mobile-link-control-v1",
		message.Type,
		message.InstallationID,
		message.ConnectionID,
		strconv.FormatInt(message.Timestamp, 10),
		message.Nonce,
	}
	_, _ = mac.Write([]byte(strings.Join(parts, "\x00")))
	return mac.Sum(nil)
}
