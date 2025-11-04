package nft

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const internalNFTMark = `antizapret-go`

type Manager struct {
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
	if err = m.initializeRule(setName, table, chain); err != nil {
		return nil, fmt.Errorf("failed to initialize rule: %w", err)
	}

	return
}

func (m *Manager) Add(srcIP, dstIP net.IP, comment string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to add `%s -> %s` to set: %w", srcIP, dstIP, err)
		}
	}()

	if err = m.conn.SetAddElements(m.set, []nftables.SetElement{
		{
			Key:     srcIP.To4(),
			Val:     dstIP.To4(),
			Counter: &expr.Counter{},
			Comment: comment,
		},
	}); err != nil {
		return
	}

	if err = m.conn.Flush(); err != nil {
		return
	}

	return
}

func (m *Manager) Delete(srcIP, dstIP net.IP) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to delete `%s -> %s` from set: %w", srcIP, dstIP, err)
		}
	}()

	if err = m.conn.SetDeleteElements(m.set, []nftables.SetElement{
		{Key: srcIP.To4(), Val: dstIP.To4()},
	}); err != nil {
		return
	}

	if err = m.conn.Flush(); err != nil {
		return
	}

	return
}

func (m *Manager) ListSet() (vals []nftables.SetElement, err error) {
	return m.conn.GetSetElements(m.set)
}

func (m *Manager) initializeChain(name string, t *nftables.Table) (chain *nftables.Chain, err error) {
	var errTemp error
	chain, errTemp = m.conn.ListChain(t, name)
	if errTemp != nil {
		chain = m.conn.AddChain(&nftables.Chain{
			Name:  name,
			Table: t,
		})
		if err = m.conn.Flush(); err != nil {
			return
		}
	}
	return
}

func (m *Manager) initializeRule(setName string, t *nftables.Table, c *nftables.Chain) (err error) {
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
					OperationType:  0x0,
					DestRegister:   0x1,
					SourceRegister: 0x0,
					Base:           0x1,
					Offset:         0x10,
					Len:            0x4,
					CsumType:       0x0,
					CsumOffset:     0x0,
					CsumFlags:      0x0,
				},
				&expr.Lookup{
					SourceRegister: 0x1,
					DestRegister:   0x1,
					IsDestRegSet:   true,
					SetID:          0x0,
					SetName:        setName,
					Invert:         false,
				},
				&expr.NAT{
					Type:        0x1,
					Family:      0x2,
					RegAddrMin:  0x1,
					RegAddrMax:  0x1,
					RegProtoMin: 0x0,
					RegProtoMax: 0x0,
					Random:      false,
					FullyRandom: false,
					Persistent:  false,
					Prefix:      false,
					Specified:   false,
				},
			},
		})
		return m.conn.Flush()
	}
	return
}

func (m *Manager) initializeSet(name string, t *nftables.Table) (set *nftables.Set, err error) {
	set, _ = m.conn.GetSetByName(t, name)
	if set == nil {
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
	} else {
		m.conn.FlushSet(set)
		if err = m.conn.Flush(); err != nil {
			return
		}
	}
	return
}

func (m *Manager) Close() error {
	return m.conn.CloseLasting()
}
