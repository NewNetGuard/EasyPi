//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

type kernelTunnel struct {
	ifce *water.Interface
	name string
	cidr string
}

func (k *kernelTunnel) Name() string {
	if k == nil {
		return ""
	}
	return k.name
}

func (k *kernelTunnel) WritePacket(packet []byte) error {
	if k == nil || k.ifce == nil {
		return fmt.Errorf("kernel tunnel is not initialized")
	}
	_, err := k.ifce.Write(packet)
	return err
}

func (k *kernelTunnel) ReadPacket(buf []byte) (int, error) {
	if k == nil || k.ifce == nil {
		return 0, fmt.Errorf("kernel tunnel is not initialized")
	}
	return k.ifce.Read(buf)
}

func (k *kernelTunnel) Close() error {
	if k == nil || k.ifce == nil {
		return nil
	}
	return k.ifce.Close()
}

func startKernelTunnel(name string, cidr string, mtu int, blockQUICUDP443 bool) (*kernelTunnel, error) {
	cfg := water.Config{DeviceType: water.TUN}
	if strings.TrimSpace(name) != "" {
		cfg.Name = name
	}

	ifce, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create TUN failed: %w", err)
	}

	tunName := ifce.Name()
	if os.Getenv("CHAMELEON_NETWORK_PREPARED") == "1" {
		return &kernelTunnel{ifce: ifce, name: tunName, cidr: cidr}, nil
	}
	runBestEffortCommand("ip", "link", "set", "dev", tunName, "mtu", fmt.Sprintf("%d", mtu))
	if err := runCommand("ip", "link", "set", "dev", tunName, "up"); err != nil {
		_ = ifce.Close()
		return nil, fmt.Errorf("set %s up failed: %w", tunName, err)
	}
	if err := runCommand("ip", "addr", "replace", cidr, "dev", tunName); err != nil {
		_ = ifce.Close()
		return nil, fmt.Errorf("assign %s to %s failed: %w", cidr, tunName, err)
	}

	if err := setupForwardingAndNAT(tunName, cidr, blockQUICUDP443); err != nil {
		_ = ifce.Close()
		return nil, fmt.Errorf("setup forwarding failed: %w", err)
	}

	return &kernelTunnel{
		ifce: ifce,
		name: tunName,
		cidr: cidr,
	}, nil
}

func setupForwardingAndNAT(tunName string, cidr string, blockQUICUDP443 bool) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid TUN CIDR %q: %w", cidr, err)
	}
	subnet := ipNet.String()

	if err := runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}

	// Throughput tuning (best effort): larger socket buffers and BBR where available.
	runBestEffortCommand("sysctl", "-w", "net.core.rmem_max=67108864")
	runBestEffortCommand("sysctl", "-w", "net.core.wmem_max=67108864")
	runBestEffortCommand("sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 67108864")
	runBestEffortCommand("sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 67108864")
	runBestEffortCommand("sysctl", "-w", "net.core.default_qdisc=fq")
	runBestEffortCommand("sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr")

	iface, err := detectDefaultInterface()
	if err != nil {
		return err
	}

	// NAT outbound tunnel traffic to the VPS public interface.
	if err := ensureIptablesRule(
		[]string{"-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"},
		[]string{"-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"},
	); err != nil {
		return err
	}

	// Permit forwarding from tunnel to internet and back.
	if err := ensureIptablesRule(
		[]string{"-C", "FORWARD", "-i", tunName, "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-i", tunName, "-j", "ACCEPT"},
	); err != nil {
		return err
	}
	if err := ensureIptablesRule(
		[]string{"-C", "FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"-A", "FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	); err != nil {
		return err
	}

	if err := ensureIptablesRule(
		[]string{"-t", "mangle", "-C", "FORWARD", "-i", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		[]string{"-t", "mangle", "-A", "FORWARD", "-i", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	); err != nil {
		return err
	}
	if err := ensureIptablesRule(
		[]string{"-t", "mangle", "-C", "FORWARD", "-o", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		[]string{"-t", "mangle", "-A", "FORWARD", "-o", tunName, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	); err != nil {
		return err
	}

	if err := syncQUICBlockRules(tunName, iface, subnet, blockQUICUDP443); err != nil {
		return err
	}

	return nil
}

func detectDefaultInterface() (string, error) {
	out, err := runCommandOutput(
		"sh", "-c",
		"ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") {print $(i+1); exit}}'",
	)
	if err != nil {
		return "", err
	}
	iface := strings.TrimSpace(out)
	if iface == "" {
		return "", fmt.Errorf("failed to detect default network interface")
	}
	return iface, nil
}

func ensureIptablesRule(checkArgs []string, addArgs []string) error {
	checkCmd := append([]string{"iptables"}, checkArgs...)
	if err := runCommand(checkCmd[0], checkCmd[1:]...); err == nil {
		return nil
	}

	addCmd := append([]string{"iptables"}, addArgs...)
	if err := runCommand(addCmd[0], addCmd[1:]...); err != nil {
		return err
	}
	return nil
}

func syncQUICBlockRules(tunName, iface, subnet string, block bool) error {
	forwardCheck := []string{"-C", "FORWARD", "-i", tunName, "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	forwardAdd := []string{"-I", "FORWARD", "1", "-i", tunName, "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	forwardDel := []string{"-D", "FORWARD", "-i", tunName, "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}

	outputCheck := []string{"-C", "OUTPUT", "-o", iface, "-p", "udp", "-s", subnet, "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	outputAdd := []string{"-I", "OUTPUT", "1", "-o", iface, "-p", "udp", "-s", subnet, "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	outputDel := []string{"-D", "OUTPUT", "-o", iface, "-p", "udp", "-s", subnet, "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}

	if block {
		if err := ensureIptablesRule(forwardCheck, forwardAdd); err != nil {
			return err
		}
		if err := ensureIptablesRule(outputCheck, outputAdd); err != nil {
			return err
		}
		return nil
	}

	removeIptablesRuleIfExists(forwardCheck, forwardDel)
	removeIptablesRuleIfExists(outputCheck, outputDel)
	return nil
}

func removeIptablesRuleIfExists(checkArgs, delArgs []string) {
	for {
		checkCmd := append([]string{"iptables"}, checkArgs...)
		if err := runCommand(checkCmd[0], checkCmd[1:]...); err != nil {
			return
		}
		delCmd := append([]string{"iptables"}, delArgs...)
		if err := runCommand(delCmd[0], delCmd[1:]...); err != nil {
			return
		}
	}
}
func runBestEffortCommand(name string, args ...string) {
	if err := runCommand(name, args...); err != nil {
		// Keep tunnel setup functional even if kernel does not support this option.
		logOperationalFailure("tun", "optional kernel tuning failed", err)
	}
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		return fmt.Errorf("%s %v failed: %v (%s)", name, args, err, msg)
	}
	return nil
}

func runCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		return "", fmt.Errorf("%s %v failed: %v (%s)", name, args, err, msg)
	}
	return string(out), nil
}
