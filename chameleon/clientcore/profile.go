package clientcore

import (
	"encoding/json"
	"math/rand"
	"os"
	"sync"
	"time"
)

// UsageProfile stores user activity patterns.
type UsageProfile struct {
	// ActivityHeatmap stores probability of activity for each hour of the day [0-23].
	// Values are 0.0 to 1.0.
	ActivityHeatmap [24]float64 `json:"activity_heatmap"`

	// PacketSizeDist stores a histogram of packet sizes.
	// We use coarse buckets: <100, 100-500, 500-1000, 1000-1500, >1500.
	PacketSizeDist map[string]int `json:"packet_size_dist"`

	// PauseDist stores a histogram of pause durations between bursts.
	// Buckets: <1s, 1-5s, 5-30s, >30s.
	PauseDist map[string]int `json:"pause_dist"`

	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`

	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
}

// ProfileManager handles profile collection and persistence.
const runtimeProfileLearningEnabled = false

type ProfileManager struct {
	mu       sync.RWMutex
	profile  *UsageProfile
	filePath string
	dirty    bool
}

// NewProfileManager creates or loads a profile manager.
func NewProfileManager(path string) *ProfileManager {
	pm := &ProfileManager{
		filePath: path,
		profile: &UsageProfile{
			PacketSizeDist: make(map[string]int),
			PauseDist:      make(map[string]int),
			FirstSeen:      time.Now(),
			LastUpdated:    time.Now(),
		},
	}

	if !runtimeProfileLearningEnabled {
		return pm
	}

	// Try to load existing
	if err := pm.load(); err != nil {
		LogOperationalFailure("profile", "existing profile unavailable; using new profile", err)
	} else {
		LogState("profile", "existing profile loaded")
	}

	// Start background saver/updater
	go pm.loop()

	return pm
}

func (pm *ProfileManager) load() error {
	data, err := os.ReadFile(pm.filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, pm.profile)
}

func (pm *ProfileManager) Save() error {
	if !runtimeProfileLearningEnabled {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.dirty {
		return nil
	}

	data, err := json.MarshalIndent(pm.profile, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file first
	tmp := pm.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmp, pm.filePath); err != nil {
		return err
	}

	// Mark clean (note: technically race here if Save called concurrently, but we use single looper)
	// Actually, we should clear dirty flag under lock.
	// But Save() is called by loop().
	return nil
}

func (pm *ProfileManager) loop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		pm.mu.Lock()
		pm.profile.LastUpdated = time.Now()
		pm.dirty = true

		// Update heatmap based on current activity if recent?
		// Actually RecordActivity updates real-time.
		// Use loop to normalize or decay stats?
		// For now just save.
		pm.mu.Unlock()

		if err := pm.Save(); err != nil {
			LogOperationalFailure("profile", "save failed", err)
		} else {
			// Clear dirty flag after successful save
			pm.mu.Lock()
			pm.dirty = false
			pm.mu.Unlock()
		}
	}
}

// RecordActivity logs a traffic event.
func (pm *ProfileManager) RecordActivity(size int, isSend bool) {
	if !runtimeProfileLearningEnabled {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.dirty = true
	hour := time.Now().Hour()

	// Increment heatmap for this hour.
	// We use a simple counter approach: slowly increase towards 1.0.
	// Current implementation: just count activity events?
	// Better: Probability = (Activity in Hour / Max Activity across all Hours).
	// But we store raw probability?
	// Let's implement activity accumulation:
	// We add small increments, maxing at 1.0.
	// Also maybe assume some decay?
	// Simple approach: The heatmap represents RELATIVE activity.
	// We just increment a counter (float for flexibility) and normalize later if needed.
	// But request says "0.0 to 1.0".
	// Let's treat it as "Intensity".
	pm.profile.ActivityHeatmap[hour] += 0.01
	if pm.profile.ActivityHeatmap[hour] > 1.0 {
		pm.profile.ActivityHeatmap[hour] = 1.0
	}

	if isSend {
		pm.profile.BytesSent += uint64(size)
	} else {
		pm.profile.BytesRecv += uint64(size)
	}

	// Packet Size Hist
	var bucket string
	if size < 100 {
		bucket = "<100"
	} else if size < 500 {
		bucket = "100-500"
	} else if size < 1000 {
		bucket = "500-1000"
	} else if size < 1500 {
		bucket = "1000-1500"
	} else {
		bucket = ">1500"
	}
	pm.profile.PacketSizeDist[bucket]++
}

// IsMature returns true if the profile has gathered enough data (48 hours).
func (pm *ProfileManager) IsMature() bool {
	if !runtimeProfileLearningEnabled {
		return false
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return time.Since(pm.profile.FirstSeen) > 48*time.Hour
}

// GetActivityLevel returns the historical activity level (0.0-1.0) for the specified hour.
func (pm *ProfileManager) GetActivityLevel(hour int) float64 {
	if !runtimeProfileLearningEnabled {
		return 0.5
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if hour < 0 || hour > 23 {
		return 0
	}
	return pm.profile.ActivityHeatmap[hour]
}

// GetTargetPacketSize returns a weighted random packet size based on history.
// Falls back to Chrome defaults if not mature or data insufficient.
func (pm *ProfileManager) GetTargetPacketSize() int {
	if !runtimeProfileLearningEnabled {
		return 1200 + rand.Intn(200)
	}

	if !pm.IsMature() {
		// Default Chrome behavior
		return getChromeDefaultPacketSize()
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Simple weighted choice based on distribution
	total := 0
	for _, count := range pm.profile.PacketSizeDist {
		total += count
	}

	if total == 0 {
		return getChromeDefaultPacketSize()
	}

	r := rand.Intn(total)
	current := 0
	for bucket, count := range pm.profile.PacketSizeDist {
		current += count
		if r < current {
			return getSizeFromBucket(bucket)
		}
	}

	return getChromeDefaultPacketSize()
}

func getChromeDefaultPacketSize() int {
	// 500-1500 biased
	r := rand.Float64()
	if r < 0.8 {
		return 500 + rand.Intn(1000) // 500-1500
	} else if r < 0.95 {
		return 100 + rand.Intn(400) // 100-500
	}
	return 1500 + rand.Intn(500)
}

func getSizeFromBucket(bucket string) int {
	switch bucket {
	case "<100":
		return 1 + rand.Intn(99)
	case "100-500":
		return 100 + rand.Intn(400)
	case "500-1000":
		return 500 + rand.Intn(500)
	case "1000-1500":
		return 1000 + rand.Intn(500)
	case ">1500":
		return 1501 + rand.Intn(2000)
	default:
		return 1000
	}
}

// Reset clears the profile.
func (pm *ProfileManager) Reset() {
	if !runtimeProfileLearningEnabled {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.profile = &UsageProfile{
		PacketSizeDist: make(map[string]int),
		PauseDist:      make(map[string]int),
		FirstSeen:      time.Now(), // Reset maturity timer
		LastUpdated:    time.Now(),
	}
	pm.dirty = true
	LogState("profile", "profile reset")
}

// GetStats returns a summary for the UI.
func (pm *ProfileManager) GetStats() UsageProfile {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	// Return copy
	return *pm.profile
}
