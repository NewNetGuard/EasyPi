package clientcore

import (
	"errors"
	"net"
	"strings"
	"time"
)

// preferredEndpointTimeout bounds a preferred endpoint (IPv6) that is not the
// last one, so a phone without a working IPv6 path reaches IPv4 quickly.
// Without any IPv6 route the dial fails at once and costs nothing.
const preferredEndpointTimeout = 3 * time.Second

// dialCandidates returns the endpoints to try in order. serverDialAddr may
// list several validated "host:port" endpoints separated by commas, most
// preferred first; without one the URL's own address is dialled.
func dialCandidates(serverDialAddr, addr string) []string {
	var candidates []string
	for _, candidate := range strings.Split(serverDialAddr, ",") {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		candidates = []string{addr}
	}
	return candidates
}

// dialFirstReachable dials the candidates in order and returns the first
// connection that completes. Every candidate but the last gets a short
// budget; the last one uses the profile's normal dial timeout.
func dialFirstReachable(candidates []string, dial func(addr string, timeout time.Duration) (net.Conn, error)) (net.Conn, error) {
	var failures []error
	for index, candidate := range candidates {
		timeout := time.Duration(0)
		if index < len(candidates)-1 {
			timeout = preferredEndpointTimeout
		}
		conn, err := dial(candidate, timeout)
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errors.New("no server endpoint to dial")
	}
	return nil, errors.Join(failures...)
}
