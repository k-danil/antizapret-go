//go:build !linux

package nft

import (
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/firewall/noop"
)

// nft требует netlink (google/nftables) — есть только на Linux. Вне его отдаём noop,
// чтобы пакет и проект собирались/тестировались на любой ОС.
func NewNftManager(chain, set string) (firewall.Manager, error) {
	return noop.New(), nil
}
