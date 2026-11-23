package mobilelink

import (
	"sync"
	"time"
)

type replayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func (cache *replayCache) accept(installationID, nonce string, now time.Time) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.items == nil {
		cache.items = make(map[string]time.Time)
	}
	for key, expires := range cache.items {
		if !expires.After(now) {
			delete(cache.items, key)
		}
	}
	key := installationID + ":" + nonce
	if _, exists := cache.items[key]; exists {
		return false
	}
	cache.items[key] = now.Add(2 * AuthWindow)
	return true
}
