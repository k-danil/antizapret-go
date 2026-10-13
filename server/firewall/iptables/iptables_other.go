//go:build !linux

package iptables

import (
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/firewall/noop"
)

func New(_, _ string) (firewall.Manager, error) {
	return noop.New(), nil
}
