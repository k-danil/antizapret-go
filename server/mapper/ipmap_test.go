package mapper

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/k-danil/antizapret-go/utils"
)

type fakeNFT struct {
	mu     sync.Mutex
	adds   int
	dels   int
	addErr error
	delErr error
	set    map[uint32]uint32 // fake -> real
}

func newFakeNFT() *fakeNFT { return &fakeNFT{set: map[uint32]uint32{}} }

func (f *fakeNFT) Add(fakeIP, realIP net.IP, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	f.adds++
	f.set[utils.IPToUint32(fakeIP)] = utils.IPToUint32(realIP)
	return nil
}

func (f *fakeNFT) Delete(fakeIP, _ net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	f.dels++
	delete(f.set, utils.IPToUint32(fakeIP))
	return nil
}

func (f *fakeNFT) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds
}

func TestMapIdempotentForSameReal(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	if err != nil {
		t.Fatal(err)
	}

	realIP := net.IPv4(8, 8, 8, 8)
	first, err := m.Map(realIP, "h")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Map(realIP, "h")
	if err != nil {
		t.Fatal(err)
	}

	if !first.Equal(second) {
		t.Fatalf("same real got different fakes: %s vs %s", first, second)
	}
	if nft.addCount() != 1 {
		t.Fatalf("nft.Add called %d times, want 1", nft.addCount())
	}

	other, err := m.Map(net.IPv4(1, 1, 1, 1), "h2")
	if err != nil {
		t.Fatal(err)
	}
	if other.Equal(first) {
		t.Fatal("different reals must map to different fakes")
	}
}

func TestMapRollbackOnAddError(t *testing.T) {
	nft := newFakeNFT()
	nft.addErr = errors.New("boom")

	// /31 => ровно один свободный fake-IP
	m, err := NewIPMapper("10.0.0.0/31", time.Hour, nft)
	if err != nil {
		t.Fatal(err)
	}

	realIP := net.IPv4(8, 8, 8, 8)
	if _, err = m.Map(realIP, "h"); err == nil {
		t.Fatal("expected error when nft.Add fails")
	}

	// если бы откат не вернул IP в пул, второй Map упал бы на "no free IPs"
	nft.addErr = nil
	fakeIP, err := m.Map(realIP, "h")
	if err != nil {
		t.Fatalf("after rollback the IP must be reusable, got: %v", err)
	}
	if fakeIP == nil {
		t.Fatal("expected a fake IP after successful retry")
	}
}

func TestMapConcurrentSameRealAllocatesOnce(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	if err != nil {
		t.Fatal(err)
	}

	realIP := net.IPv4(8, 8, 8, 8)
	const n = 50
	results := make([]net.IP, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ip, mErr := m.Map(realIP, "h")
			if mErr != nil {
				t.Errorf("Map: %v", mErr)
				return
			}
			results[i] = ip
		}(i)
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if !results[i].Equal(results[0]) {
			t.Fatalf("concurrent Map of same real returned different fakes: %s vs %s", results[0], results[i])
		}
	}
	if nft.addCount() != 1 {
		t.Fatalf("nft.Add called %d times, want 1 (no double allocation)", nft.addCount())
	}
}

func TestCleanReturnsIPOnSuccess(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Nanosecond, nft)
	if err != nil {
		t.Fatal(err)
	}

	realIP := net.IPv4(8, 8, 8, 8)
	if _, err = m.Map(realIP, "h"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond) // дать записи истечь

	if err = m.Clean(); err != nil {
		t.Fatal(err)
	}
	if nft.dels != 1 {
		t.Fatalf("nft.Delete called %d times, want 1", nft.dels)
	}

	// запись истекла и удалена — следующий Map должен заново аллоцировать (новый Add)
	if _, err = m.Map(realIP, "h"); err != nil {
		t.Fatal(err)
	}
	if nft.addCount() != 2 {
		t.Fatalf("nft.Add called %d times, want 2 (re-alloc after clean)", nft.addCount())
	}
}

func TestCleanKeepsMappingOnDeleteError(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Nanosecond, nft)
	if err != nil {
		t.Fatal(err)
	}

	realIP := net.IPv4(8, 8, 8, 8)
	fakeIP, err := m.Map(realIP, "h")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)

	nft.delErr = errors.New("boom")
	if err = m.Clean(); err == nil {
		t.Fatal("expected aggregated error when nft.Delete fails")
	}

	// маппинг должен остаться (ретрай в следующем цикле), а не потеряться/утечь
	again, err := m.Map(realIP, "h")
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(fakeIP) {
		t.Fatalf("mapping changed after failed delete: %s vs %s", fakeIP, again)
	}
	if nft.addCount() != 1 {
		t.Fatalf("nft.Add called %d times, want 1 (mapping was kept, not re-created)", nft.addCount())
	}
}
