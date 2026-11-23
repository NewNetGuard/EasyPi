//go:build windows

package clientcore

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// dnsAdapterState saves the original DNS configuration of one network adapter
// so it can be restored when the proxy stops.
type dnsAdapterState struct {
	index        int  // interface index
	wasAutomatic bool // true if DNS was set by DHCP (no static servers)
	origServers  []string
}

// applyWindowsDNS sets the system DNS to 127.0.0.1 on all active IPv4 adapters
// and returns a slice of states that can be passed to restoreWindowsDNS.
func applyWindowsDNS(dnsListenIP string) ([]dnsAdapterState, error) {
	// List active interfaces and their current DNS servers using PowerShell.
	// We target only UP, non-loopback, IPv4-capable interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var states []dnsAdapterState

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		hasIPv4 := false
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip != nil && ip.To4() != nil {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}

		// Get current DNS servers for this interface.
		origServers, err := getWindowsDNS(iface.Index)
		if err != nil {
			LogOperationalFailure("dns-cfg", "adapter DNS read failed", err)
			continue
		}

		state := dnsAdapterState{
			index:        iface.Index,
			origServers:  origServers,
			wasAutomatic: len(origServers) == 0,
		}
		states = append(states, state)

		// Set DNS to our local proxy.
		if err := setWindowsDNS(iface.Index, dnsListenIP); err != nil {
			LogOperationalFailure("dns-cfg", "adapter DNS update failed", err)
			continue
		}
		LogState("dns-cfg", "adapter DNS updated")
	}

	if len(states) == 0 {
		return nil, fmt.Errorf("no active IPv4 adapters found or DNS could not be set")
	}
	return states, nil
}

// restoreWindowsDNS restores each adapter to its original DNS configuration.
func restoreWindowsDNS(states []dnsAdapterState) {
	for _, s := range states {
		var err error
		if s.wasAutomatic || len(s.origServers) == 0 {
			err = resetWindowsDNS(s.index) // back to DHCP
		} else {
			err = setWindowsDNS(s.index, strings.Join(s.origServers, `",""`))
		}
		if err != nil {
			LogOperationalFailure("dns-cfg", "adapter DNS restore failed", err)
		} else {
			LogState("dns-cfg", "adapter DNS restored")
		}
	}
}

// getWindowsDNS returns the current static DNS server addresses for the
// given interface index. Returns empty slice when DHCP/automatic.
func getWindowsDNS(ifaceIndex int) ([]string, error) {
	ps := fmt.Sprintf(
		`(Get-DnsClientServerAddress -InterfaceIndex %d -AddressFamily IPv4).ServerAddresses`,
		ifaceIndex,
	)
	out, err := powershell(ps)
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		s := strings.TrimSpace(line)
		if s != "" && net.ParseIP(s) != nil {
			servers = append(servers, s)
		}
	}
	return servers, nil
}

// setWindowsDNS points the given interface at the specified DNS server.
func setWindowsDNS(ifaceIndex int, serverAddr string) error {
	// Strip port if present (we just need the IP).
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr // no port — use as-is
	}

	ps := fmt.Sprintf(
		`Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses "%s"`,
		ifaceIndex, host,
	)
	_, err = powershell(ps)
	return err
}

// resetWindowsDNS restores the interface to DHCP-assigned DNS.
func resetWindowsDNS(ifaceIndex int) error {
	ps := fmt.Sprintf(
		`Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses`,
		ifaceIndex,
	)
	_, err := powershell(ps)
	return err
}

// powershell executes a PowerShell one-liner and returns stdout.
func powershell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("powershell: %w\nstderr: %s", err, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("powershell: %w", err)
	}
	return string(out), nil
}
