// Package noop — DNAT-бэкенд-заглушка: ничего не делает. Применяется как `backend: noop`
// и как реализация nft/iptables вне Linux, чтобы проект собирался и тестировался везде.
package noop

import "github.com/k-danil/antizapret-go/server/firewall"

type Manager struct{}

func New() firewall.Manager { return Manager{} }

func (Manager) Add(firewall.Mapping) error        { return nil }
func (Manager) Delete(firewall.Mapping) error     { return nil }
func (Manager) List() ([]firewall.Mapping, error) { return nil, nil }
func (Manager) Close() error                      { return nil }
