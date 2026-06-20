package iptables

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDNATRule(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		wantOK   bool
		wantFake string
		wantReal string
	}{
		{
			name:     "host rule with /32",
			rule:     "-A antizapret -d 10.0.0.5/32 -j DNAT --to-destination 1.2.3.4",
			wantOK:   true,
			wantFake: "10.0.0.5",
			wantReal: "1.2.3.4",
		},
		{
			name:     "host rule without mask",
			rule:     "-A antizapret -d 10.0.0.9 -j DNAT --to-destination 8.8.8.8",
			wantOK:   true,
			wantFake: "10.0.0.9",
			wantReal: "8.8.8.8",
		},
		{
			name:   "chain creation line",
			rule:   "-N antizapret",
			wantOK: false,
		},
		{
			name:   "policy line",
			rule:   "-P PREROUTING ACCEPT",
			wantOK: false,
		},
		{
			name:   "missing to-destination",
			rule:   "-A antizapret -d 10.0.0.5/32 -j DNAT",
			wantOK: false,
		},
		{
			name:   "missing dest",
			rule:   "-A antizapret -j DNAT --to-destination 1.2.3.4",
			wantOK: false,
		},
		{
			name:   "empty",
			rule:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := parseDNATRule(tt.rule)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			require.True(t, net.ParseIP(tt.wantFake).Equal(m.Fake), "fake %s", m.Fake)
			require.True(t, net.ParseIP(tt.wantReal).Equal(m.Real), "real %s", m.Real)
		})
	}
}
