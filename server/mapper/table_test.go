package mapper

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func staleEntry(t *testing.T, tbl *mappingTable, real uint32) {
	t.Helper()
	tbl.mu.RLock()
	e := tbl.m[real]
	tbl.mu.RUnlock()
	require.NotNil(t, e)
	e.lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())
}

func TestMappingTableSetGet(t *testing.T) {
	tbl := newMappingTable()

	_, ok := tbl.get(1)
	require.False(t, ok, "пустая таблица — промах")

	tbl.set(1, 100)
	f, ok := tbl.get(1)
	require.True(t, ok)
	require.Equal(t, uint32(100), f)

	tbl.set(1, 101)
	f, _ = tbl.get(1)
	require.Equal(t, uint32(101), f)
}

func TestMappingTableExpired(t *testing.T) {
	tbl := newMappingTable()
	tbl.set(1, 100)
	tbl.set(2, 200)
	staleEntry(t, tbl, 1)

	exp := tbl.expired(time.Minute)
	require.Equal(t, []pair{{real: 1, fake: 100}}, exp)

	_, ok := tbl.get(1)
	require.False(t, ok, "истёкшая запись удалена")
	f, ok := tbl.get(2)
	require.True(t, ok)
	require.Equal(t, uint32(200), f, "свежая запись остаётся")
}

func TestMappingTableGetRefreshesTTL(t *testing.T) {
	tbl := newMappingTable()
	tbl.set(1, 100)
	staleEntry(t, tbl, 1)

	_, ok := tbl.get(1)
	require.True(t, ok)

	require.Empty(t, tbl.expired(time.Minute), "после touch запись не истекает (sliding-TTL)")
}

func TestMappingTableHasNoTouch(t *testing.T) {
	tbl := newMappingTable()
	tbl.set(1, 100)
	staleEntry(t, tbl, 1)

	require.True(t, tbl.has(1))
	require.False(t, tbl.has(2))

	require.Len(t, tbl.expired(time.Minute), 1, "has не продлевает TTL")
}

func TestMappingTableConcurrent(t *testing.T) {
	tbl := newMappingTable()
	const n = 1000
	for i := range uint32(n) {
		tbl.set(i, i+1000)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for i := range uint32(n) {
				tbl.get(i)
				if i%100 == 0 {
					tbl.set(i, i+2000)
				}
			}
		})
	}
	wg.Go(func() {
		for range 50 {
			tbl.expired(time.Nanosecond)
		}
	})
	wg.Wait()
}

func BenchmarkMappingTableGetParallel(b *testing.B) {
	tbl := newMappingTable()
	const n = 10000
	for i := range uint32(n) {
		tbl.set(i, i+1000)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var i uint32
		for pb.Next() {
			tbl.get(i % n)
			i++
		}
	})
}
