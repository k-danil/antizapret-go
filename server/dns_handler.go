package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/log"
)

type DNSHandler struct {
	*Server
	client   *dns.Client
	upstream net.Conn
	timeout  time.Duration
	ttl      time.Duration
}

func NewDNSHandler(s *Server, addr string, timeout, ttl time.Duration) (d *DNSHandler, err error) {
	var netConn net.Conn
	if netConn, err = net.DialTimeout("udp", addr, timeout); err != nil {
		err = fmt.Errorf("failed to connect to upstream: %w", err)
		return nil, err
	}
	return &DNSHandler{
		Server:   s,
		client:   dns.NewClient(),
		upstream: netConn,
		timeout:  timeout,
		ttl:      ttl,
	}, nil
}

func (d *DNSHandler) Close() error {
	return d.upstream.Close()
}

func (d *DNSHandler) DNSHandler(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, d.timeout)
	defer cancel()

	if err := r.Unpack(); err != nil {
		log.L.Warnw("unpack request failed", "err", err)
		r.Rcode = dns.RcodeFormatError
		_, _ = r.WriteTo(w)
		return
	}

	resp, _, err := d.client.ExchangeWithConn(ctx, r, d.upstream)
	if err != nil || resp == nil {
		if err != nil {
			log.L.Warnw("upstream failed", "err", err)
		}
		r.Rcode = dns.RcodeServerFailure
		_, _ = r.WriteTo(w)
		return
	}

	for _, q := range r.Question {
		switch q.(type) {
		case *dns.A:
			var newAnswer []*dns.A
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					newAnswer = append(newAnswer, a)
				}
			}
			resp.Answer = make([]dns.RR, 0, len(newAnswer))
			for _, ans := range newAnswer {
				var fake net.IP
				if fake, err = d.ipMapper.Map(ans.A, ans.Hdr.Name); err != nil {
					log.L.Errorw("map failed", "err", err)
					r.Rcode = dns.RcodeServerFailure
					_, _ = r.WriteTo(w)
					return
				}

				hdr := ans.Hdr
				hdr.TTL = uint32(d.ttl.Seconds())
				resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: fake})
			}
		default:
			continue
		}
	}

	_, _ = resp.WriteTo(w)
}
