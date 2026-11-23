package prismlink

import "sync"

const replayWindowSize = 1024

// replayWindow accepts substantial UDP reordering while rejecting duplicates
// without allocating per packet. A ring slot can only collide with a sequence
// that has already fallen outside the authenticated window.
type replayWindow struct {
	mu      sync.Mutex
	largest uint64
	seen    [replayWindowSize]uint64
}

func (window *replayWindow) accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	if sequence <= window.largest && window.largest-sequence >= replayWindowSize {
		return false
	}
	slot := sequence % replayWindowSize
	if window.seen[slot] == sequence {
		return false
	}
	window.seen[slot] = sequence
	if sequence > window.largest {
		window.largest = sequence
	}
	return true
}
