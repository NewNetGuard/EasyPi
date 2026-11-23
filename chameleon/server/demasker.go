package main

import (
	"fmt"
	"sync"
	"time"

	"chameleon/shared"
)

const (
	maxLegacyAssemblies = 256
	maxLegacyChunks     = 64
	maxLegacyPacketSize = 65535
)

// chunkEntry stores a received chunk pending reassembly.
type chunkEntry struct {
	data     []byte
	received time.Time
}

// packetAssembly tracks chunks for a single original packet.
type packetAssembly struct {
	chunks      map[uint16][]byte
	totalChunks uint16
	bytes       int
	created     time.Time
}

// Demasker handles demasking and reassembly of Chameleon protocol packets.
type Demasker struct {
	psk        []byte
	assemblies map[uint32]*packetAssembly // packetID → assembly
	mu         sync.Mutex
	outputChan chan []byte
	stopChan   chan struct{}
}

// NewDemasker creates a new Demasker instance.
func NewDemasker(psk []byte) *Demasker {
	d := &Demasker{
		psk:        psk,
		assemblies: make(map[uint32]*packetAssembly),
		outputChan: make(chan []byte, 100),
		stopChan:   make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// DemaskPlaintext processes an already authenticated inner payload.
func (d *Demasker) DemaskPlaintext(plaintext []byte) ([]byte, error) {
	header, payload, err := shared.Unpack(d.psk, plaintext)
	if err != nil {
		return nil, fmt.Errorf("unpack failed: %w", err)
	}

	// 3. Handle Packet Type
	if header.Type == shared.PacketTypeCover || header.Type == shared.PacketTypePadding {
		// Ignore cover traffic and separate padding packets
		return nil, nil
	}
	if header.Type != shared.PacketTypeData {
		return nil, fmt.Errorf("unsupported packet type: %d", header.Type)
	}
	if header.TotalChunks == 0 || header.ChunkIndex >= header.TotalChunks {
		return nil, fmt.Errorf("invalid chunk metadata: index %d of %d", header.ChunkIndex, header.TotalChunks)
	}
	if header.TotalChunks > maxLegacyChunks {
		return nil, fmt.Errorf("packet has too many chunks: %d", header.TotalChunks)
	}
	if len(payload) > maxLegacyPacketSize {
		return nil, fmt.Errorf("packet payload is too large: %d", len(payload))
	}

	// 4. If single chunk, return directly
	if header.TotalChunks == 1 {
		if header.ChunkIndex != 0 {
			return nil, fmt.Errorf("invalid single-chunk index: %d", header.ChunkIndex)
		}
		// NOTE: Payload might contain inline padding if it was padded to meet minSize.
		// Since we don't have an 'OriginalLength' field, we rely on the upstream (VPN/IP stack)
		// to ignore trailing garbage, OR we should parse the IP header here.
		// For now, we pass it as-is.
		return payload, nil
	}

	// 5. Multi-chunk packet — add to assembler
	d.mu.Lock()
	defer d.mu.Unlock()

	assembly, exists := d.assemblies[header.PacketID]
	if !exists {
		if len(d.assemblies) >= maxLegacyAssemblies {
			return nil, fmt.Errorf("too many incomplete packet assemblies")
		}
		assembly = &packetAssembly{
			chunks:      make(map[uint16][]byte),
			totalChunks: header.TotalChunks,
			created:     time.Now(),
		}
		d.assemblies[header.PacketID] = assembly
	} else if assembly.totalChunks != header.TotalChunks {
		return nil, fmt.Errorf("inconsistent total chunks for packet %d", header.PacketID)
	}

	if _, exists := assembly.chunks[header.ChunkIndex]; exists {
		return nil, fmt.Errorf("duplicate chunk %d for packet %d", header.ChunkIndex, header.PacketID)
	}
	if assembly.bytes+len(payload) > maxLegacyPacketSize {
		delete(d.assemblies, header.PacketID)
		return nil, fmt.Errorf("reassembled packet is too large")
	}

	// Copy the exact payload so an incomplete assembly cannot retain a larger
	// backing buffer supplied by the transport.
	assembly.chunks[header.ChunkIndex] = append([]byte(nil), payload...)
	assembly.bytes += len(payload)

	// 6. Check if all chunks received
	if uint16(len(assembly.chunks)) == assembly.totalChunks {
		// Reassemble in order
		result := make([]byte, 0, assembly.bytes)
		for i := uint16(0); i < assembly.totalChunks; i++ {
			chunk, ok := assembly.chunks[i]
			if !ok {
				return nil, fmt.Errorf("missing packet chunk")
			}
			result = append(result, chunk...)
		}

		// Clean up
		delete(d.assemblies, header.PacketID)

		// Emit completed packet
		select {
		case d.outputChan <- result:
		default:
			logRateLimitedEvent("demasker", "packet dropped because output queue is full")
		}

		return result, nil
	}

	// Not all chunks yet — return nil (no complete packet yet)
	return nil, nil
}

// Output returns the channel where reassembled packets are emitted.
func (d *Demasker) Output() <-chan []byte {
	return d.outputChan
}

// Stop shuts down the demasker.
func (d *Demasker) Stop() {
	close(d.stopChan)
	close(d.outputChan)
}

// cleanupLoop removes stale incomplete assemblies (older than 30 seconds).
func (d *Demasker) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for id, assembly := range d.assemblies {
				if now.Sub(assembly.created) > 30*time.Second {
					logRateLimitedEvent("demasker", "discarded stale incomplete packet")
					delete(d.assemblies, id)
				}
			}
			d.mu.Unlock()
		}
	}
}
