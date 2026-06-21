package mapper

import (
	"encoding/binary"
	"net"
	"sync"

	"github.com/k-danil/antizapret-go/utils"
)

type ipPool struct {
	mu sync.Mutex

	network   uint32
	cursor    uint32
	broadcast uint32

	freed []uint32
	head  int

	adopted  map[uint32]struct{}
	maxAdopt uint32
}

func newIPPool(cidr *net.IPNet) *ipPool {
	network := utils.IPToUint32(cidr.IP)
	wildcard := ^binary.BigEndian.Uint32(cidr.Mask)
	return &ipPool{
		network:   network,
		cursor:    network,
		broadcast: network | wildcard,
	}
}

func (p *ipPool) inRange(ip uint32) bool {
	return ip >= p.network && ip < p.broadcast
}

func (p *ipPool) capacity() uint32 {
	return p.broadcast - p.network
}

func (p *ipPool) isAdopted(ip uint32) (ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok = p.adopted[ip]
	return
}

func (p *ipPool) markAdopted(ip uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.adopted == nil {
		p.adopted = make(map[uint32]struct{})
	}
	p.adopted[ip] = struct{}{}
	if ip > p.maxAdopt {
		p.maxAdopt = ip
	}
}

func (p *ipPool) allocate() (ip uint32, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.head < len(p.freed) {
		ip = p.freed[p.head]
		p.head++
		if p.head == len(p.freed) {
			p.freed = p.freed[:0]
			p.head = 0
		}
		ok = true
		return
	}

	for p.cursor < p.broadcast {
		ip = p.cursor
		p.cursor++

		if p.adopted == nil {
			ok = true
			return
		}

		_, taken := p.adopted[ip]
		if p.cursor > p.maxAdopt {
			p.adopted = nil
		}
		if taken {
			continue
		}
		ok = true
		return
	}

	ip, ok = 0, false
	return
}

func (p *ipPool) release(ip uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// сдвигаем живой хвост в начало, иначе backing-массив freed растёт при постоянном churn
	if p.head > 0 && p.head >= len(p.freed)-p.head {
		n := copy(p.freed, p.freed[p.head:])
		p.freed = p.freed[:n]
		p.head = 0
	}
	p.freed = append(p.freed, ip)
}
