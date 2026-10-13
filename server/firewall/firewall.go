package firewall

import "net/netip"

type Mapping struct {
	Fake netip.Addr
	Real netip.Addr
}

type Manager interface {
	Add(m Mapping) error
	// Delete идемпотентен: отсутствующий маппинг не ошибка — Clean повторяет весь срез после сбоя.
	Delete(mappings []Mapping) error
	List() ([]Mapping, error)
	Close() error
}
