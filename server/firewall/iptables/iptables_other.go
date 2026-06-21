//go:build !linux

package iptables

import (
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/firewall/noop"
)

// iptables вне Linux не функционирует (нужен бинарь iptables и ядро) — noop ради
// кросс-сборки и тестов.
func New(chain, fakeCIDR string) (firewall.Manager, error) {
	return noop.New(), nil
}
