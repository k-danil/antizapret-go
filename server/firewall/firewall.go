// Package firewall описывает контракт DNAT-бэкенда (fake → real). Реализации —
// в подпакетах nft и iptables; выбор бэкенда делает слой wiring (cmd). Пакет
// намеренно не импортирует реализации, чтобы потребители интерфейса (server)
// не тянули Linux-only зависимости и оставались кросс-платформенно тестируемыми.
package firewall

import "net"

type Manager interface {
	Add(fakeIP, realIP net.IP, comment string) error
	Delete(fakeIP, realIP net.IP) error
	Close() error
}
