package mapper

import (
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/utils"
	"github.com/stretchr/testify/require"
)

type fakeNFT struct {
	adds   int
	delErr error
	set    map[uint32]uint32 // fake -> real
}

func newFakeNFT() *fakeNFT { return &fakeNFT{set: map[uint32]uint32{}} }

func (f *fakeNFT) Add(mp firewall.Mapping) error {
	f.adds++
	f.set[utils.AddrToUint32(mp.Fake)] = utils.AddrToUint32(mp.Real)
	return nil
}

func (f *fakeNFT) Delete(mappings []firewall.Mapping) error {
	if f.delErr != nil {
		return f.delErr
	}
	for _, mp := range mappings {
		delete(f.set, utils.AddrToUint32(mp.Fake))
	}
	return nil
}

func (f *fakeNFT) List() ([]firewall.Mapping, error) { return nil, nil }
func (f *fakeNFT) Close() error                      { return nil }

func TestCleanRetriesFailedDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nft := newFakeNFT()
		m, err := NewIPMapper("10.0.0.0/24", time.Nanosecond, nft)
		require.NoError(t, err)

		realIP := netip.MustParseAddr("8.8.8.8")
		fakeOld, err := m.Map(realIP)
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)

		nft.delErr = errors.New("boom")
		require.Error(t, m.Clean(), "ошибка delete агрегируется")

		fakeNew, err := m.Map(realIP)
		require.NoError(t, err)
		require.NotEqual(t, fakeOld, fakeNew, "после неудачного delete real получает свежий fake")
		require.Equal(t, 2, nft.adds)

		nft.delErr = nil
		time.Sleep(2 * time.Millisecond)
		require.NoError(t, m.Clean())
		require.Empty(t, nft.set, "в ядре нет ни сирот, ни утечек")
	})
}
