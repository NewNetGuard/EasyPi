package main

import (
	"bytes"
	"strings"
	"testing"

	"chameleon/shared"
)

func newTestDemasker(t *testing.T) (*Demasker, []byte) {
	t.Helper()
	psk := []byte("demasker-security-test-key")
	d := NewDemasker(psk)
	t.Cleanup(d.Stop)
	return d, psk
}

func TestDemaskerRejectsInvalidChunkMetadata(t *testing.T) {
	d, psk := newTestDemasker(t)
	tests := []struct {
		name        string
		chunkIndex  uint16
		totalChunks uint16
	}{
		{name: "zero total", chunkIndex: 0, totalChunks: 0},
		{name: "index outside total", chunkIndex: 2, totalChunks: 2},
		{name: "too many chunks", chunkIndex: 0, totalChunks: maxLegacyChunks + 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet := shared.Pack(psk, 1, tc.chunkIndex, tc.totalChunks, shared.PacketTypeData, []byte("x"))
			if _, err := d.DemaskPlaintext(packet); err == nil {
				t.Fatal("expected invalid metadata to be rejected")
			}
		})
	}
}

func TestDemaskerBoundsIncompleteAssemblies(t *testing.T) {
	d, psk := newTestDemasker(t)
	for id := uint32(0); id < maxLegacyAssemblies; id++ {
		packet := shared.Pack(psk, id, 0, 2, shared.PacketTypeData, []byte("x"))
		if result, err := d.DemaskPlaintext(packet); err != nil || result != nil {
			t.Fatalf("assembly %d: result=%v err=%v", id, result, err)
		}
	}

	packet := shared.Pack(psk, maxLegacyAssemblies, 0, 2, shared.PacketTypeData, []byte("x"))
	if _, err := d.DemaskPlaintext(packet); err == nil || !strings.Contains(err.Error(), "too many incomplete") {
		t.Fatalf("expected assembly limit error, got %v", err)
	}
	if got := len(d.assemblies); got != maxLegacyAssemblies {
		t.Fatalf("assembly count grew past limit: %d", got)
	}
}

func TestDemaskerRejectsConflictingAndDuplicateChunks(t *testing.T) {
	d, psk := newTestDemasker(t)
	first := shared.Pack(psk, 7, 0, 2, shared.PacketTypeData, []byte("first"))
	if _, err := d.DemaskPlaintext(first); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DemaskPlaintext(first); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	conflicting := shared.Pack(psk, 7, 1, 3, shared.PacketTypeData, []byte("second"))
	if _, err := d.DemaskPlaintext(conflicting); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("expected inconsistent total error, got %v", err)
	}
}

func TestDemaskerBoundsReassembledPacketSize(t *testing.T) {
	d, psk := newTestDemasker(t)
	firstPayload := bytes.Repeat([]byte{'a'}, maxLegacyPacketSize)
	first := shared.Pack(psk, 9, 0, 2, shared.PacketTypeData, firstPayload)
	if _, err := d.DemaskPlaintext(first); err != nil {
		t.Fatal(err)
	}
	second := shared.Pack(psk, 9, 1, 2, shared.PacketTypeData, []byte("b"))
	if _, err := d.DemaskPlaintext(second); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected packet size error, got %v", err)
	}
	if _, exists := d.assemblies[9]; exists {
		t.Fatal("oversized assembly was not discarded")
	}
}

func TestDemaskerReassemblesValidChunks(t *testing.T) {
	d, psk := newTestDemasker(t)
	first := shared.Pack(psk, 11, 0, 2, shared.PacketTypeData, []byte("hello "))
	second := shared.Pack(psk, 11, 1, 2, shared.PacketTypeData, []byte("world"))
	if result, err := d.DemaskPlaintext(first); err != nil || result != nil {
		t.Fatalf("first chunk: result=%v err=%v", result, err)
	}
	result, err := d.DemaskPlaintext(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "hello world" {
		t.Fatalf("unexpected result: %q", result)
	}
}
