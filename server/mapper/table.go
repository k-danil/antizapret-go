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
	t.m[real] = e
	t.mu.Unlock()
}

func (t *mappingTable) has(real uint32) (ok bool) {
	t.mu.RLock()
	_, ok = t.m[real]
	t.mu.RUnlock()
	return
}

func (t *mappingTable) expired(ttl time.Duration) (out []pair) {
	cutoff := time.Now().Add(-ttl).UnixNano()

	t.mu.Lock()
	defer t.mu.Unlock()

	for real, e := range t.m {
		if e.lastSeen.Load() <= cutoff {
			out = append(out, pair{real: real, fake: e.fake})
			delete(t.m, real)
		}
	}
	return
}
