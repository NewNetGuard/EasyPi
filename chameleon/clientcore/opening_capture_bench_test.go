package clientcore

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"chameleon/shared"
)

// TestOpeningCapture opens carrier connections one after another on the
// isolated stand (tools/connection-opening) so that a packet capture holds
// many connection openings: OPEN_CONNECTIONS fresh sessions, each followed by
// OPEN_EPOCHS epoch replacements. It only generates traffic; the analysis
// runs on the capture.
func TestOpeningCapture(t *testing.T) {
	keysPath := os.Getenv("OPEN_KEYS")
	if keysPath == "" {
		t.Skip("set OPEN_KEYS, OPEN_SERVER to run on the opening stand")
	}
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	var keys loadKeys
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	authKey, _ := hex.DecodeString(keys.ClientAuthKey)
	connections := loadEnvInt("OPEN_CONNECTIONS", 10)
	epochs := loadEnvInt("OPEN_EPOCHS", 3)
	settle := time.Duration(loadEnvInt("OPEN_SETTLE_MS", 1500)) * time.Millisecond

	for i := 0; i < connections; i++ {
		device := keys.DeviceIDs[i%len(keys.DeviceIDs)]
		cfg := Config{
			ServerAddress:          os.Getenv("OPEN_SERVER"),
			PSKKey:                 hex.EncodeToString(shared.MobilePSK(authKey, device)),
			TransportKey:           keys.PSKKey,
			Protocol:               "http2",
			BufferSize:             1000,
			ReconnectInterval:      5,
			FingerprintMode:        "auto",
			BootstrapCertSHA256:    keys.CertSHA256,
			RealityServerPublicKey: keys.RealityPublicKey,
			RealityShieldPreset:    "ip",
		}
		conn, problem := buildMobileConnection(cfg, NewProfileManager(""), newPacketQueueInjector(64))
		if problem != "" {
			t.Fatalf("connection %d: %s", i, problem)
		}
		if err := connectWithRetries(conn, 30*time.Second); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		conn.Start()
		time.Sleep(settle)
		for e := 0; e < epochs; e++ {
			if err := conn.transport.RefreshTransport(); err != nil {
				t.Errorf("connection %d epoch %d: %v", i, e, err)
			}
			time.Sleep(settle)
		}
		conn.Stop()
		time.Sleep(500 * time.Millisecond)
	}
}
