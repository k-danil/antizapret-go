package mapper

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeNFT struct {
	mu     sync.Mutex
	adds   int
	dels   int
	addErr error
	delErr error
	set    map[uint32]uint32  // fake -> real
	raw    []firewall.Mapping // произвольные записи "из ядра" для List (напр. не-v4)
}

func newFakeNFT() *fakeNFT { return &fakeNFT{set: map[uint32]uint32{}} }

func (f *fakeNFT) Add(mp firewall.Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	f.adds++
	f.set[utils.IPToUint32(mp.Fake)] = utils.IPToUint32(mp.Real)
	return nil
}

func (f *fakeNFT) Delete(mappings []firewall.Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	for _, mp := range mappings {
		f.dels++
		delete(f.set, utils.IPToUint32(mp.Fake))
	}
	return nil
}

func (f *fakeNFT) Close() error { return nil }

func (f *fakeNFT) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds
}

func (f *fakeNFT) setLen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.set)
}

func (f *fakeNFT) List() ([]firewall.Mapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]firewall.Mapping, 0, len(f.set)+len(f.raw))
	for fake, realIP := range f.set {
		out = append(out, firewall.Mapping{
			Fake: utils.Uint32ToIP(fake),
			Real: utils.Uint32ToIP(realIP),
		})
	}
	out = append(out, f.raw...)
	return out, nil
}

func TestMapIdempotentForSameReal(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	realIP := net.IPv4(8, 8, 8, 8)
	first, err := m.Map(realIP)
	require.NoError(t, err)
	second, err := m.Map(realIP)
	require.NoError(t, err)

	require.True(t, first.Equal(second), "один real → один fake")
	require.Equal(t, 1, nft.addCount())

	other, err := m.Map(net.IPv4(1, 1, 1, 1))
	require.NoError(t, err)
	require.False(t, other.Equal(first), "разные real → разные fake")
}

func TestMapRollbackOnAddError(t *testing.T) {
	nft := newFakeNFT()
	nft.addErr = errors.New("boom")

	// /31 => ровно один свободный fake-IP
	m, err := NewIPMapper("10.0.0.0/31", time.Hour, nft)
	require.NoError(t, err)

	realIP := net.IPv4(8, 8, 8, 8)
	_, err = m.Map(realIP)
	require.Error(t, err, "Map должен вернуть ошибку при сбое nft.Add")

	// если бы откат не вернул IP в пул, второй Map упал бы на "no free IPs"
	nft.addErr = nil
	fakeIP, err := m.Map(realIP)
	require.NoError(t, err, "после отказа IP должен переиспользоваться")
	require.NotNil(t, fakeIP)
}

func TestMapConcurrentSameRealAllocatesOnce(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	realIP := net.IPv4(8, 8, 8, 8)
	const n = 50
	results := make([]net.IP, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			ip, mErr := m.Map(realIP)
			if !assert.NoError(t, mErr) {
				return
			}
			results[i] = ip
		})
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		require.Truef(t, results[i].Equal(results[0]), "конкурентный Map одного real: %s vs %s", results[0], results[i])
	}
	require.Equal(t, 1, nft.addCount(), "без двойной аллокации")
}

func TestCleanReturnsIPOnSuccess(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Nanosecond, nft)
	require.NoError(t, err)

	realIP := net.IPv4(8, 8, 8, 8)
	_, err = m.Map(realIP)
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond) // дать записи истечь

	require.NoError(t, m.Clean())
	require.Equal(t, 1, nft.dels)

	_, err = m.Map(realIP)
	require.NoError(t, err)
	require.Equal(t, 2, nft.addCount(), "re-alloc после clean")
}

func TestCleanRetriesFailedDelete(t *testing.T) {
	nft := newFakeNFT()
	m, err := NewIPMapper("10.0.0.0/24", time.Nanosecond, nft)
	require.NoError(t, err)

	realIP := net.IPv4(8, 8, 8, 8)
	fakeOld, err := m.Map(realIP)
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)

	nft.delErr = errors.New("boom")
	require.Error(t, m.Clean(), "ошибка delete агрегируется")

	fakeNew, err := m.Map(realIP)
	require.NoError(t, err)
	require.False(t, fakeOld.Equal(fakeNew), "после неудачного delete real получает свежий fake")
	require.Equal(t, 2, nft.addCount())

	nft.delErr = nil
	time.Sleep(2 * time.Millisecond)
	require.NoError(t, m.Clean())
	require.Equal(t, 0, nft.setLen(), "в ядре нет ни сирот, ни утечек")
}

func TestAdoptSeedsExistingMappings(t *testing.T) {
	nft := newFakeNFT()
	realIP := net.IPv4(8, 8, 8, 8)
	fakeIP := net.IPv4(10, 0, 0, 7)
	nft.set[utils.IPToUint32(fakeIP)] = utils.IPToUint32(realIP) // состояние ядра с прошлого запуска

	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	got, err := m.Map(realIP)
	require.NoError(t, err)
	require.True(t, got.Equal(fakeIP), "усыновлённый маппинг переиспользован")
	require.Equal(t, 0, nft.addCount(), "маппинг усыновлён, Add не звался")
}

func TestAdoptExcludesFakeFromPool(t *testing.T) {
	nft := newFakeNFT()
	adoptedFake := net.IPv4(10, 0, 0, 0) // первый адрес, который иначе выдал бы cursor
	nft.set[utils.IPToUint32(adoptedFake)] = utils.IPToUint32(net.IPv4(8, 8, 8, 8))

	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	other, err := m.Map(net.IPv4(1, 1, 1, 1))
	require.NoError(t, err)
	require.False(t, other.Equal(adoptedFake), "пул не выдал усыновлённый fake")
}

func TestAdoptDropsOutOfRange(t *testing.T) {
	nft := newFakeNFT()
	stale := net.IPv4(192, 168, 0, 1) // вне нового fake_cidr
	nft.set[utils.IPToUint32(stale)] = utils.IPToUint32(net.IPv4(8, 8, 8, 8))

	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	require.Equal(t, 0, nft.setLen(), "стейл вне диапазона вычищен из ядра")
	got, err := m.Map(net.IPv4(8, 8, 8, 8))
	require.NoError(t, err)
	require.True(t, m.pool.inRange(utils.IPToUint32(got)), "fake должен быть в диапазоне пула")
}

func TestAdoptSkipsNonIPv4(t *testing.T) {
	nft := newFakeNFT()
	realIP := net.IPv4(8, 8, 8, 8)
	fakeIP := net.IPv4(10, 0, 0, 7)
	nft.set[utils.IPToUint32(fakeIP)] = utils.IPToUint32(realIP)
	// чужой не-v4 элемент в наборе ядра — IPToUint32 на нём паникует без guard
	nft.raw = []firewall.Mapping{{Fake: net.ParseIP("2001:db8::1"), Real: net.IPv4(1, 1, 1, 1)}}

	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	got, err := m.Map(realIP)
	require.NoError(t, err)
	require.True(t, got.Equal(fakeIP), "валидный маппинг усыновлён")
	require.Equal(t, 0, nft.addCount())
}

func TestAdoptDropsDuplicateReal(t *testing.T) {
	nft := newFakeNFT()
	realU := utils.IPToUint32(net.IPv4(8, 8, 8, 8))
	nft.set[utils.IPToUint32(net.IPv4(10, 0, 0, 5))] = realU // два fake на один real
	nft.set[utils.IPToUint32(net.IPv4(10, 0, 0, 6))] = realU

	m, err := NewIPMapper("10.0.0.0/24", time.Hour, nft)
	require.NoError(t, err)

	require.Equal(t, 1, nft.setLen(), "дубликат real: лишний fake вычищен")
	_, err = m.Map(net.IPv4(8, 8, 8, 8))
	require.NoError(t, err)
	require.Equal(t, 0, nft.addCount(), "real усыновлён")
}
