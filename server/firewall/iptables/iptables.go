package iptables

import (
	"fmt"
	"net"

	goipt "github.com/coreos/go-iptables/iptables"
)

const table = "nat"

type Manager struct {
	ipt   *goipt.IPTables
	chain string
}

func New(chain, fakeCIDR string) (m *Manager, err error) {
	var ipt *goipt.IPTables
	if ipt, err = goipt.New(); err != nil {
		return nil, fmt.Errorf("failed to init iptables: %w", err)
	}

	// создаём цепочку и очищаем её — чистое состояние на старте
	if err = ipt.ClearChain(table, chain); err != nil {
		return nil, fmt.Errorf("failed to init chain `%s`: %w", chain, err)
	}
	// заворачиваем трафик к fake-пулу в нашу цепочку (идемпотентно)
	if err = ipt.AppendUnique(table, "PREROUTING", "-d", fakeCIDR, "-j", chain); err != nil {
		return nil, fmt.Errorf("failed to add PREROUTING jump: %w", err)
	}

	return &Manager{ipt: ipt, chain: chain}, nil
}

// rule без комментария: iptables -D матчит правило целиком, а Delete домена не знает,
// поэтому Add и Delete должны строить идентичный rulespec.
func (m *Manager) rule(fakeIP, realIP net.IP) []string {
	return []string{"-d", fakeIP.String(), "-j", "DNAT", "--to-destination", realIP.String()}
}

func (m *Manager) Add(fakeIP, realIP net.IP, _ string) error {
	return m.ipt.Append(table, m.chain, m.rule(fakeIP, realIP)...)
}

func (m *Manager) Delete(fakeIP, realIP net.IP) error {
	return m.ipt.DeleteIfExists(table, m.chain, m.rule(fakeIP, realIP)...)
}

func (m *Manager) Close() error { return nil }
