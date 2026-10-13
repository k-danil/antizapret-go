//go:build linux

package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	goipt "github.com/coreos/go-iptables/iptables"
	"github.com/k-danil/antizapret-go/server/firewall"
)

const (
	table         = "nat"
	preroute      = "PREROUTING"
	targetDNAT    = "DNAT"
	flagDest      = "-d"
	flagJump      = "-j"
	flagToDest    = "--to-destination"
	hostMaskSfx   = "/32"
	appendRuleTag = "-A"
)

type Manager struct {
	mu sync.Mutex

	ipt   *goipt.IPTables
	chain string
}

func New(chain, fakeCIDR string) (m *Manager, err error) {
	var ipt *goipt.IPTables
	if ipt, err = goipt.New(); err != nil {
		return nil, fmt.Errorf("failed to init iptables: %w", err)
	}

	var exists bool
	if exists, err = ipt.ChainExists(table, chain); err != nil {
		return nil, fmt.Errorf("failed to check chain `%s`: %w", chain, err)
	}
	if !exists {
		if err = ipt.NewChain(table, chain); err != nil {
			return nil, fmt.Errorf("failed to create chain `%s`: %w", chain, err)
		}
	}

	if err = ipt.AppendUnique(table, preroute, flagDest, fakeCIDR, flagJump, chain); err != nil {
		return nil, fmt.Errorf("failed to add PREROUTING jump: %w", err)
	}

	return &Manager{ipt: ipt, chain: chain}, nil
}

func (m *Manager) rule(fakeIP, realIP netip.Addr) []string {
	return []string{flagDest, fakeIP.String(), flagJump, targetDNAT, flagToDest, realIP.String()}
}

func (m *Manager) Add(mp firewall.Mapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ipt.AppendUnique(table, m.chain, m.rule(mp.Fake, mp.Real)...)
}

func (m *Manager) Delete(mappings []firewall.Mapping) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mp := range mappings {
		if delErr := m.ipt.DeleteIfExists(table, m.chain, m.rule(mp.Fake, mp.Real)...); delErr != nil {
			err = errors.Join(err, delErr)
		}
	}
	return
}

func (m *Manager) List() (out []firewall.Mapping, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var rules []string
	if rules, err = m.ipt.List(table, m.chain); err != nil {
		return nil, fmt.Errorf("failed to list chain `%s`: %w", m.chain, err)
	}

	for _, r := range rules {
		if mp, ok := parseDNATRule(r); ok {
			out = append(out, mp)
		}
	}
	return
}

func parseDNATRule(rule string) (m firewall.Mapping, ok bool) {
	fields := strings.Fields(rule)
	if len(fields) == 0 || fields[0] != appendRuleTag {
		return
	}

	var fakeStr, realStr string
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case flagDest:
			fakeStr = strings.TrimSuffix(fields[i+1], hostMaskSfx)
		case flagToDest:
			realStr = fields[i+1]
		}
	}

	fakeIP, fakeErr := netip.ParseAddr(fakeStr)
	realIP, realErr := netip.ParseAddr(realStr)
	if fakeErr != nil || realErr != nil || !fakeIP.Is4() || !realIP.Is4() {
		return
	}
	return firewall.Mapping{Fake: fakeIP, Real: realIP}, true
}

func (m *Manager) Close() error { return nil }
