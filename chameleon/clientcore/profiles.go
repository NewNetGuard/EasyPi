package clientcore

import (
	"math/rand"
	"time"
)

// ProfileParams defines the packet characteristics for a traffic profile.
type ProfileParams struct {
	MinPacketSize int
	MaxPacketSize int
	MinInterval   time.Duration
	MaxInterval   time.Duration
	BurstSize     int // how many packets to send in a burst without pause
}

// Predefined traffic profiles
var (
	BrowsingProfile = ProfileParams{
		MinPacketSize: 200,
		MaxPacketSize: 1400,
		MinInterval:   50 * time.Millisecond,
		MaxInterval:   300 * time.Millisecond,
		BurstSize:     3,
	}

	VideoProfile = ProfileParams{
		MinPacketSize: 1000,
		MaxPacketSize: 1500,
		MinInterval:   5 * time.Millisecond,
		MaxInterval:   30 * time.Millisecond,
		BurstSize:     10,
	}

	SystemProfile = ProfileParams{
		MinPacketSize: 64,
		MaxPacketSize: 300,
		MinInterval:   500 * time.Millisecond,
		MaxInterval:   5000 * time.Millisecond,
		BurstSize:     1,
	}

	IdleProfile = ProfileParams{
		MinPacketSize: 64,
		MaxPacketSize: 150,
		MinInterval:   2000 * time.Millisecond,
		MaxInterval:   10000 * time.Millisecond,
		BurstSize:     1,
	}
)

// GetProfile returns the ProfileParams for the given traffic mode.
func GetProfile(mode string) ProfileParams {
	switch mode {
	case "video":
		return VideoProfile
	case "browsing":
		return BrowsingProfile
	case "system":
		return SystemProfile
	case "idle":
		return IdleProfile
	default:
		return BrowsingProfile
	}
}

// RandomizeParams adds random deviation of ±15% to all profile parameters.
// This prevents identical traffic patterns across sessions.
func RandomizeParams(params ProfileParams) ProfileParams {
	randomize := func(value int) int {
		deviation := float64(value) * 0.15
		offset := rand.Float64()*2*deviation - deviation
		result := int(float64(value) + offset)
		if result < 1 {
			result = 1
		}
		return result
	}

	randomizeDuration := func(d time.Duration) time.Duration {
		deviation := float64(d) * 0.15
		offset := rand.Float64()*2*deviation - deviation
		result := time.Duration(float64(d) + offset)
		if result < time.Millisecond {
			result = time.Millisecond
		}
		return result
	}

	return ProfileParams{
		MinPacketSize: randomize(params.MinPacketSize),
		MaxPacketSize: randomize(params.MaxPacketSize),
		MinInterval:   randomizeDuration(params.MinInterval),
		MaxInterval:   randomizeDuration(params.MaxInterval),
		BurstSize:     params.BurstSize, // burst size stays the same
	}
}
