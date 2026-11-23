package clientcore

import (
	"sync"
	"time"
)

const (
	analysisWindow = 50              // number of recent packets to analyze
	idleTimeout    = 5 * time.Second // no activity = idle
)

// TrafficProfile represents the current traffic behavior.
type TrafficProfile struct {
	Mode          string        // "browsing" / "video" / "system" / "idle"
	AvgPacketSize int           // average packet size in bytes
	AvgInterval   time.Duration // average interval between packets
	Direction     string        // "bidirectional" / "download" / "upload"
}

// packetRecord stores info about a single captured packet.
type packetRecord struct {
	size      int
	timestamp time.Time
	outbound  bool // true = upload, false = download
}

// Analyzer analyzes real user traffic to determine the current behavior profile.
type Analyzer struct {
	mu      sync.Mutex
	records []packetRecord
}

// NewAnalyzer creates a new traffic Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		records: make([]packetRecord, 0, analysisWindow),
	}
}

// Analyze records a packet for analysis.
func (a *Analyzer) Analyze(packetSize int, outbound bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	record := packetRecord{
		size:      packetSize,
		timestamp: time.Now(),
		outbound:  outbound,
	}

	a.records = append(a.records, record)

	// Keep only the last N records
	if len(a.records) > analysisWindow {
		a.records = a.records[len(a.records)-analysisWindow:]
	}
}

// GetCurrentProfile returns the current traffic profile based on recent packets.
func (a *Analyzer) GetCurrentProfile() TrafficProfile {
	a.mu.Lock()
	defer a.mu.Unlock()

	profile := TrafficProfile{
		Mode:      "idle",
		Direction: "bidirectional",
	}

	if len(a.records) == 0 {
		return profile
	}

	// Check for idle: no activity for more than 5 seconds
	lastRecord := a.records[len(a.records)-1]
	if time.Since(lastRecord.timestamp) > idleTimeout {
		return profile
	}

	// Calculate averages
	totalSize := 0
	outboundCount := 0
	inboundCount := 0
	var totalInterval time.Duration
	intervalCount := 0

	for i, r := range a.records {
		totalSize += r.size
		if r.outbound {
			outboundCount++
		} else {
			inboundCount++
		}
		if i > 0 {
			interval := r.timestamp.Sub(a.records[i-1].timestamp)
			totalInterval += interval
			intervalCount++
		}
	}

	profile.AvgPacketSize = totalSize / len(a.records)

	if intervalCount > 0 {
		profile.AvgInterval = totalInterval / time.Duration(intervalCount)
	}

	// Determine direction
	total := outboundCount + inboundCount
	if total > 0 {
		outRatio := float64(outboundCount) / float64(total)
		if outRatio > 0.7 {
			profile.Direction = "upload"
		} else if outRatio < 0.3 {
			profile.Direction = "download"
		} else {
			profile.Direction = "bidirectional"
		}
	}

	// Determine mode based on criteria
	switch {
	case profile.AvgPacketSize > 1000 && profile.AvgInterval < 30*time.Millisecond && profile.Direction == "download":
		// VIDEO: large packets, fast interval, mostly download
		profile.Mode = "video"
	case profile.AvgPacketSize >= 200 && profile.AvgPacketSize <= 1000 &&
		profile.AvgInterval >= 50*time.Millisecond && profile.AvgInterval <= 300*time.Millisecond &&
		profile.Direction == "bidirectional":
		// BROWSING: medium packets, medium interval, bidirectional
		profile.Mode = "browsing"
	case profile.AvgPacketSize < 200 && profile.AvgInterval > 500*time.Millisecond:
		// SYSTEM: small packets, slow interval
		profile.Mode = "system"
	default:
		// Default to browsing if nothing matches clearly
		profile.Mode = "browsing"
	}

	return profile
}
