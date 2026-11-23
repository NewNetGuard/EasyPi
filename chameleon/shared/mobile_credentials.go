package shared

import (
	"crypto/hmac"
	"crypto/sha256"
)

// MobilePSK is a device credential, never a public routing/marker key.
func MobilePSK(master []byte, deviceID string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("easypi/mobile-auth/v1/" + deviceID))
	return mac.Sum(nil)
}
