package clientcore

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDialCandidatesKeepTheConfiguredOrder(t *testing.T) {
	got := dialCandidates("[2001:db8::7]:443, 198.51.100.7:443", "vpn.example:443")
	want := []string{"[2001:db8::7]:443", "198.51.100.7:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dialCandidates = %v, want %v", got, want)
	}
	if got := dialCandidates("", "vpn.example:443"); !reflect.DeepEqual(got, []string{"vpn.example:443"}) {
		t.Fatalf("without a dial address the URL address is dialled, got %v", got)
	}
}

func TestDialFirstReachablePrefersTheFirstAndFallsBack(t *testing.T) {
	type attempt struct {
		addr    string
		timeout time.Duration
	}
	var attempts []attempt
	client, server := net.Pipe()
	defer server.Close()
	conn, err := dialFirstReachable([]string{"[2001:db8::7]:443", "198.51.100.7:443"}, func(addr string, timeout time.Duration) (net.Conn, error) {
		attempts = append(attempts, attempt{addr, timeout})
		if strings.HasPrefix(addr, "[") {
			return nil, errors.New("network is unreachable")
		}
		return client, nil
	})
	if err != nil || conn != client {
		t.Fatalf("dialFirstReachable = %v, %v", conn, err)
	}
	want := []attempt{{"[2001:db8::7]:443", preferredEndpointTimeout}, {"198.51.100.7:443", 0}}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("attempts = %v, want %v", attempts, want)
	}
}

func TestDialFirstReachableReportsEveryFailure(t *testing.T) {
	_, err := dialFirstReachable([]string{"a:443", "b:443"}, func(addr string, _ time.Duration) (net.Conn, error) {
		return nil, errors.New("refused " + addr)
	})
	if err == nil || !strings.Contains(err.Error(), "refused a:443") || !strings.Contains(err.Error(), "refused b:443") {
		t.Fatalf("err = %v", err)
	}
}
