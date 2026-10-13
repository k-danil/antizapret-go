//go:build linux

package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/k-danil/antizapret-go/server/firewall"
)

const internalNFTMark = `antizapret-go`

type Manager struct {
	// батч conn общий: без mu чужой Flush отправит или откатит наши элементы
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

	k, v := mp.Fake.As4(), mp.Real.As4()
	if err = m.conn.SetAddElements(m.set, []nftables.SetElement{
		{
			Key: k[:],
			Val: v[:],
		},
	}); err != nil {
		return
	}

	if err = m.conn.Flush(); err != nil {
		return
	}

	return
}

func (m *Manager) Delete(mappings []firewall.Mapping) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(mappings) == 0 {
		return
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to delete %d elements from set: %w", len(mappings), err)
		}
	}()

	if err = m.conn.SetDeleteElements(m.set, toSetElements(mappings)); err != nil {
		return
	}
	if err = m.conn.Flush(); err == nil {
		return
	}
	// батч атомарен: один отсутствующий элемент откатывает весь Flush
	if !errors.Is(err, os.ErrNotExist) {
		return
	}

	var existing []nftables.SetElement
	if existing, err = m.conn.GetSetElements(m.set); err != nil {
		return
	}
	present := intersectPresent(mappings, existing)
	if len(present) == 0 {
		return
	}
	if err = m.conn.SetDeleteElements(m.set, toSetElements(present)); err != nil {
		return
	}
	err = m.conn.Flush()
	return
}

func toSetElements(mappings []firewall.Mapping) (elems []nftables.SetElement) {
	elems = make([]nftables.SetElement, len(mappings))
	for i, mp := range mappings {
		k, v := mp.Fake.As4(), mp.Real.As4()
		elems[i] = nftables.SetElement{Key: k[:], Val: v[:]}
	}
	return
}

func intersectPresent(mappings []firewall.Mapping, existing []nftables.SetElement) (present []firewall.Mapping) {
	live := make(map[netip.Addr]struct{}, len(existing))
	for _, e := range existing {
		if k, ok := netip.AddrFromSlice(e.Key); ok {
			live[k.Unmap()] = struct{}{}
		}
	}
	for _, mp := range mappings {
		if _, ok := live[mp.Fake]; ok {
			present = append(present, mp)
		}
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
		k, _ := netip.AddrFromSlice(e.Key)
		v, _ := netip.AddrFromSlice(e.Val)
		out = append(out, firewall.Mapping{Fake: k.Unmap(), Real: v.Unmap()})
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
