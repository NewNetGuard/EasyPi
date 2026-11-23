package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const clientIdentityContext = "chameleon-client-identity-v1"

// ClientIDForPSK derives the only client identity accepted for an installation
// credential. A peer that knows one shared PSK cannot mint arbitrary client IDs
// to evade session quotas. The ID reveals no PSK material.
func ClientIDForPSK(psk []byte) string {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(clientIdentityContext))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
