//go:build !windows

package clientcore

// applyWindowsDNS is a no-op on non-Windows platforms.
// On Linux/macOS, DNS can be redirected via resolv.conf or system settings.
func applyWindowsDNS(dnsListenIP string) ([]dnsAdapterState, error) {
	return nil, nil
}

// restoreWindowsDNS is a no-op on non-Windows platforms.
func restoreWindowsDNS(states []dnsAdapterState) {}

// dnsAdapterState placeholder for cross-platform compilation.
type dnsAdapterState struct{}
