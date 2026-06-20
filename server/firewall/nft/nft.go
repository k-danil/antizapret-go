package nft

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/k-danil/antizapret-go/server/firewall"
)

const internalNFTMark = `antizapret-go`

type Manager struct {
	// conn не потокобезопасен: копит батч и шлёт Flush по одному сокету
	mu sync.Mutex

	conn *nftables.Conn

	set *nftables.Set
}

func NewNftManager(chainName, setName string) (m *Manager, err error) {
	var conn *nftables.Conn
	if conn, err = nftables.New(nftables.AsLasting()); err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	m = &Manager{
		conn: conn,
	}

	var table *nftables.Table
	if table, err = conn.ListTable("nat"); err != nil {
		return nil, fmt.Errorf("failed to list table: %w", err)
	}

	var chain *nftables.Chain
	if chain, err = m.initializeChain(chainName, table); err != nil {
		return nil, fmt.Errorf("failed to initialize chain: %w", err)
	}
	if m.set, err = m.initializeSet(setName, table); err != nil {
		return nil, fmt.Errorf("failed to initialize set: %w", err)
	}
	if err = m.initializeRule(table, chain); err != nil {
		return nil, fmt.Errorf("failed to initialize rule: %w", err)
	}

	return
}

func (m *Manager) Add(mp firewall.Mapping) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to add `%s -> %s` to set: %w", mp.Fake, mp.Real, err)
		}
	}()

	if err = m.conn.SetAddElements(m.set, []nftables.SetElement{
		{
			Key: mp.Fake.To4(),
			Val: mp.Real.To4(),
		},
	}); err != nil {
		return
	}

	if err = m.conn.Flush(); err != nil {
		return
	}

	return
}

func (m *Manager) Delete(mp firewall.Mapping) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to delete `%s -> %s` from set: %w", mp.Fake, mp.Real, err)
		}
	}()

	if err = m.conn.SetDeleteElements(m.set, []nftables.SetElement{
		{Key: mp.Fake.To4(), Val: mp.Real.To4()},
	}); err != nil {
		return
	}

	if err = m.conn.Flush(); errors.Is(err, os.ErrNotExist) {
		err = nil // элемент уже отсутствует — удаление идемпотентно
	}
	return
}

func (m *Manager) List() (out []firewall.Mapping, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var elems []nftables.SetElement
	if elems, err = m.conn.GetSetElements(m.set); err != nil {
		return nil, fmt.Errorf("failed to list set elements: %w", err)
	}

	out = make([]firewall.Mapping, 0, len(elems))
	for _, e := range elems {
		out = append(out, firewall.Mapping{
			Fake: net.IP(e.Key).To4(),
			Real: net.IP(e.Val).To4(),
		})
	}
	return
}

func (m *Manager) initializeChain(name string, t *nftables.Table) (chain *nftables.Chain, err error) {
	var errTemp error
	chain, errTemp = m.conn.ListChain(t, name)
	if errTemp != nil {
		chain = m.conn.AddChain(&nftables.Chain{
			Name:     name,
			Table:    t,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityFilter,
		})
		if err = m.conn.Flush(); err != nil {
			return
		}
	}
	return
}

func (m *Manager) initializeRule(t *nftables.Table, c *nftables.Chain) (err error) {
	r, _ := m.conn.GetRules(t, c)
	var exists bool
	for _, rule := range r {
		if string(rule.UserData) == internalNFTMark {
			exists = true
			break
		}
	}
	if !exists {
		m.conn.AddRule(&nftables.Rule{
			Table:    t,
			Chain:    c,
			UserData: []byte(internalNFTMark),
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					DestRegister:  1,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        16,
					Len:           4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					DestRegister:   1,
					IsDestRegSet:   true,
					SetID:          m.set.ID,
					SetName:        m.set.Name,
				},
				&expr.NAT{
					Type:       expr.NATTypeDestNAT,
					Family:     syscall.AF_INET,
					RegAddrMin: 1,
					RegAddrMax: 1,
				},
			},
		})
		return m.conn.Flush()
	}
	return
}

func (m *Manager) initializeSet(name string, t *nftables.Table) (set *nftables.Set, err error) {
	// существующий набор переживает рестарт и усыновляется маппером
	if set, _ = m.conn.GetSetByName(t, name); set != nil {
		return
	}

	set = &nftables.Set{
		Table:    t,
		Name:     name,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
		Comment:  internalNFTMark,
	}
	if err = m.conn.AddSet(set, nil); err != nil {
		return
	}
	if err = m.conn.Flush(); err != nil {
		return
	}
	return
}

func (m *Manager) Close() error {
	return m.conn.CloseLasting()
}
