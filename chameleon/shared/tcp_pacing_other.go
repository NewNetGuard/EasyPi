//go:build !linux

package shared

import "net"

func readTCPPacingTelemetry(net.Conn) (tcpPacingTelemetry, bool) {
	return tcpPacingTelemetry{}, false
}
