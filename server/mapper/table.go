package mapper

import (
	"sync"
	"sync/atomic"
	"time"
)

type pair struct{ real, fake uint32 }

type mapping struct {
	fake     uint32
	lastSeen atomic.Int64
}

type mappingTable struct {
	mu sync.RWMutex
	m  map[uint32]*mapping
}

func newMappingTable() *mappingTable {
	return &mappingTable{m: make(map[uint32]*mapping)}
}

func (t *mappingTable) get(real uint32) (fake uint32, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	e, ok := t.m[real]
	if ok {
		e.lastSeen.Store(time.Now().UnixNano())
		fake = e.fake
	}
	return
}

func (t *mappingTable) set(real, fake uint32) {
	e := &mapping{fake: fake}
	e.lastSeen.Store(time.Now().UnixNano())

	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[real] = e
}

func (t *mappingTable) has(real uint32) (ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok = t.m[real]
	return
}

func (t *mappingTable) Len() (n int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n = len(t.m)
	return
}

func (t *mappingTable) expired(ttl time.Duration) (out []pair) {
	cutoff := time.Now().Add(-ttl).UnixNano()

	t.mu.Lock()
	defer t.mu.Unlock()

	for realU, e := range t.m {
		if e.lastSeen.Load() <= cutoff {
			out = append(out, pair{real: realU, fake: e.fake})
			delete(t.m, realU)
		}
	}
	return
}
