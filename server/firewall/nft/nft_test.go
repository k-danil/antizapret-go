//go:build linux

package nft

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/stretchr/testify/require"
)

func TestIntersectPresent(t *testing.T) {
	// mapping.Fake приходит из Uint32ToIP → 16-байтовый net.IP,
	// а ключи снимка сета — 4-байтовые: пересечение обязано их сматчить
	mp := func(fake, real string) firewall.Mapping {
		return firewall.Mapping{Fake: net.ParseIP(fake), Real: net.ParseIP(real)}
	}
	elem := func(key net.IP) nftables.SetElement {
		return nftables.SetElement{Key: key}
	}

	tests := []struct {
		name     string
		mappings []firewall.Mapping
		existing []nftables.SetElement
		wantFake []string
	}{
		{
			name:     "all present",
			mappings: []firewall.Mapping{mp("10.0.0.1", "8.8.8.8"), mp("10.0.0.2", "1.1.1.1")},
			existing: []nftables.SetElement{elem(net.IPv4(10, 0, 0, 1).To4()), elem(net.IPv4(10, 0, 0, 2).To4())},
			wantFake: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "some absent are dropped",
			mappings: []firewall.Mapping{mp("10.0.0.1", "8.8.8.8"), mp("10.0.0.2", "1.1.1.1")},
			existing: []nftables.SetElement{elem(net.IPv4(10, 0, 0, 2).To4())},
			wantFake: []string{"10.0.0.2"},
		},
		{
			name:     "16-byte snapshot key still matches 16-byte fake",
			mappings: []firewall.Mapping{mp("10.0.0.1", "8.8.8.8")},
			existing: []nftables.SetElement{elem(net.ParseIP("10.0.0.1"))},
			wantFake: []string{"10.0.0.1"},
		},
		{
			name:     "empty snapshot keeps nothing",
			mappings: []firewall.Mapping{mp("10.0.0.1", "8.8.8.8")},
			existing: nil,
			wantFake: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			present := intersectPresent(tt.mappings, tt.existing)

			var got []string
			for _, p := range present {
				got = append(got, p.Fake.String())
			}
			require.Equal(t, tt.wantFake, got)
		})
	}
}
