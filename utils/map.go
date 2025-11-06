package utils

import (
	"sync"
	"time"
)

type MapEntry[T any] struct {
	Value      T
	accessTime time.Time
}

type Pair[K comparable, V any] struct {
	Key   K
	Value V
}

type SafeTTLMap[K comparable, V any] struct {
	m   map[K]MapEntry[V]
	ttl time.Duration
	mx  sync.Mutex
}

func NewTTLMap[K comparable, V any](capacity int, ttl time.Duration) *SafeTTLMap[K, V] {
	return &SafeTTLMap[K, V]{
		m:   make(map[K]MapEntry[V], capacity),
		ttl: ttl,
	}
}

func (m *SafeTTLMap[K, V]) Get(k K) (V, bool) {
	m.mx.Lock()
	defer m.mx.Unlock()
	v, ok := m.m[k]
	if ok {
		m.m[k] = MapEntry[V]{Value: v.Value, accessTime: time.Now()}
	}
	return v.Value, ok
}

func (m *SafeTTLMap[K, V]) Set(k K, v V) {
	m.mx.Lock()
	defer m.mx.Unlock()
	m.m[k] = MapEntry[V]{Value: v, accessTime: time.Now()}
}

func (m *SafeTTLMap[K, V]) Clean() []Pair[K, V] {
	m.mx.Lock()
	defer m.mx.Unlock()
	var res []Pair[K, V]
	for k, v := range m.m {
		if time.Since(v.accessTime) > m.ttl {
			res = append(res, Pair[K, V]{k, v.Value})
			delete(m.m, k)
		}
	}
	return res
}
