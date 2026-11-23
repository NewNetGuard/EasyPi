//go:build linux

// Command chameleon-client is a headless Linux client for the Chameleon stealth
// tunnel. It is the non-Android counterpart of the VpnService in the Android app:
// it owns a TUN device and shuttles IP packets between the kernel and the
// cross-platform client core (chameleon/clientcore).
//
// Intended target: Linux (incl. Raspberry Pi arm64) as a gateway. EasyPi drives
// the policy routing + kill-switch around the TUN this process creates; the
// process itself only creates the interface and moves packets.
//
// Build (Pi):  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/chameleon-client
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"

	"chameleon/clientcore"
)

// localConfig holds the fields this shim needs on top of the client-core config.
// It shares the same JSON file as the client-core Config; unknown keys are
// ignored on each side.
type localConfig struct {
	ServerAddr  string `json:"server_address"`
	TunName     string `json:"tun_name"`      // TUN device name (default cham0)
	TunAddr     string `json:"tun_addr"`      // CIDR set on the TUN (default 10.10.0.2/32)
	MTU         int    `json:"mtu"`           // default 1420 (matches the Android client)
	StatusFile  string `json:"status_file"`   // optional: GetStats() JSON is written here
	ProfilePath string `json:"profile_path"`  // optional: persisted traffic profile
	ConfigTUN   *bool  `json:"configure_tun"` // if false, EasyPi configures the iface instead
	// TCPStreamRoute is the route the client keeps for device TCP while the
	// server offers streams (only with a socket-activated listener).
	TCPStreamRoute *tcpStreamRoute `json:"tcp_stream_route"`
}

func main() {
	cfgPath := flag.String("config", "chameleon-client.json", "path to client config JSON")
	tunFlag := flag.String("tun", "", "override TUN device name")
	statusFlag := flag.String("status", "", "override status file path")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		clientcore.FatalOperationalFailure("client", "configuration read failed", err)
	}

	var lc localConfig
	_ = json.Unmarshal(raw, &lc)
	if *tunFlag != "" {
		lc.TunName = *tunFlag
	}
	if *statusFlag != "" {
		lc.StatusFile = *statusFlag
	}
	if lc.TunName == "" {
		lc.TunName = "cham0"
	}
	if lc.TunAddr == "" {
		lc.TunAddr = "10.10.0.2/32"
	}
	if lc.MTU == 0 {
		lc.MTU = 1420
	}
	configureTUN := lc.ConfigTUN == nil || *lc.ConfigTUN

	client := clientcore.NewMobileClient()
	if lc.ProfilePath != "" {
		client.SetProfilePath(lc.ProfilePath)
	}
	if e := client.SetConfigJSON(string(raw)); e != "" {
		clientcore.FatalOperationalFailure("client", "configuration rejected", errors.New(e))
	}

	// Create the TUN. Needs CAP_NET_ADMIN (root) on Linux.
	ifce, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: lc.TunName},
	})
	if err != nil {
		clientcore.FatalOperationalFailure("tun", "interface creation failed", err)
	}
	name := ifce.Name()
	clientcore.LogState("tun", "interface created")
	if configureTUN {
		setupInterface(name, lc.TunAddr, lc.MTU)
	} else {
		clientcore.LogState("tun", "interface configuration delegated to EasyPi")
	}

	clientcore.LogState("client", "connecting")
	if e := client.StartClient(); e != "" {
		clientcore.WriteFailureStatus(lc.StatusFile, lc.ServerAddr, e)
		_ = ifce.Close()
		clientcore.FatalOperationalFailure("client", "start failed", errors.New(e))
	}
	clientcore.LogState("client", "connected")

	// TCP streams: only when EasyPi passed a transparent listener (socket
	// activation). Without it, TCP keeps using the packet tunnel.
	streamCtx, stopStreams := context.WithCancel(context.Background())
	defer stopStreams()
	if listener, err := activatedTCPListener(); err != nil {
		clientcore.LogOperationalFailure("tcp", "activated listener unusable", err)
	} else if listener != nil {
		clientcore.LogState("tcp", "TCP stream relay active")
		go serveTCPStreams(streamCtx, listener, clientStreamOpener(client))
		if lc.TCPStreamRoute != nil && lc.TCPStreamRoute.valid() {
			routeDone := make(chan struct{})
			go func() {
				defer close(routeDone)
				manageStreamRoute(streamCtx, *lc.TCPStreamRoute, client.TCPStreamsAvailable)
			}()
			// On shutdown the route is removed before the process exits, so
			// device TCP falls back to the packet tunnel's table at once.
			defer func() {
				stopStreams()
				select {
				case <-routeDone:
				case <-time.After(2 * time.Second):
				}
			}()
		} else if lc.TCPStreamRoute != nil {
			clientcore.LogState("tcp", "stream route configuration rejected; TCP stays on the packet tunnel")
		}
	}

	stop := make(chan struct{})
	var running atomic.Bool
	running.Store(true)

	// Uplink: kernel TUN -> tunnel.
	go func() {
		buf := make([]byte, 65535)
		for running.Load() {
			n, err := ifce.Read(buf)
			if err != nil {
				if running.Load() {
					clientcore.LogOperationalFailure("uplink", "TUN read failed", err)
				}
				return
			}
			if n <= 0 {
				continue
			}
			pkt := make([]byte, n) // copy: buf is reused on the next Read
			copy(pkt, buf[:n])
			// Non-IPv4 / malformed packets are silently dropped by the core.
			_ = client.PushPacket(pkt)
		}
	}()

	// Downlink: tunnel -> kernel TUN. PullPacketBatch returns framed
	// [2-byte big-endian length][packet] records; it is non-blocking.
	go func() {
		for running.Load() {
			batch := client.PullPacketBatch(64, 256*1024)
			if len(batch) == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			off := 0
			for off+2 <= len(batch) {
				plen := int(binary.BigEndian.Uint16(batch[off : off+2]))
				off += 2
				if plen <= 0 || off+plen > len(batch) {
					break
				}
				if _, err := ifce.Write(batch[off : off+plen]); err != nil && running.Load() {
					clientcore.LogOperationalFailure("downlink", "TUN write failed", err)
				}
				off += plen
			}
		}
	}()

	// Optional status file for EasyPi to read.
	if lc.StatusFile != "" {
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if s := client.GetStats(); s != "" {
						_ = os.WriteFile(lc.StatusFile, []byte(s), 0o600)
					}
				}
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	clientcore.LogState("client", "shutting down")
	running.Store(false)
	stopStreams()
	close(stop)
	client.StopClient()
	_ = ifce.Close()
	if lc.StatusFile != "" {
		_ = os.Remove(lc.StatusFile)
	}
}

// setupInterface brings the TUN up with an address and MTU via iproute2. Best
// effort: failures are logged, not fatal (EasyPi may own this).
func setupInterface(name, addr string, mtu int) {
	run := func(args ...string) {
		if _, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			clientcore.LogOperationalFailure("tun", "interface configuration command failed", err)
		}
	}
	run("link", "set", "dev", name, "up")
	run("link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
	run("addr", "add", addr, "dev", name)
	clientcore.LogState("tun", "interface configured")
}
