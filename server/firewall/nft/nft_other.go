//go:build !linux

package nft

import (
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/firewall/noop"
)

func NewNftManager(_, _ string) (firewall.Manager, error) {
	return noop.New(), nil
}
