package shared

import "testing"

func TestClientIDForPSKIsStableAndCredentialBound(t *testing.T) {
	first := ClientIDForPSK([]byte("first-secret"))
	if first != ClientIDForPSK([]byte("first-secret")) {
		t.Fatal("client identity is not deterministic")
	}
	if first == ClientIDForPSK([]byte("second-secret")) {
		t.Fatal("different credentials produced the same client identity")
	}
	if len(first) != 32 {
		t.Fatalf("unexpected client identity length: %d", len(first))
	}
}
