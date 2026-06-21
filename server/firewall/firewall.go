// Package firewall описывает контракт DNAT-бэкенда (fake → real). Реализации —
// в подпакетах nft, iptables и noop; выбор бэкенда делает слой wiring (cmd). Пакет
// намеренно не импортирует реализации, чтобы потребители интерфейса (server)
// не тянули Linux-only зависимости и оставались кросс-платформенно тестируемыми.
package firewall

import "net"

type Mapping struct {
	Fake net.IP
	Real net.IP
}

type Manager interface {
	Add(m Mapping) error
	Delete(m Mapping) error
	List() ([]Mapping, error)
	Close() error
}
