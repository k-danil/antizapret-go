package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
)

type Uplink struct {
	name   string
	client *dns.Client
	conn   net.Conn
}

type Resolver struct {
	uplinks []Uplink
}

func NewResolver(config []cfg.Upstream) (r *Resolver, err error) {
	r = &Resolver{
		uplinks: make([]Uplink, 0, len(config)),
	}

	for _, u := range config {
		var tempUplink Uplink

		var details *url.URL
		details, err = url.Parse(u.DSN)
		if err != nil {
			err = fmt.Errorf("failed to parse upstream `%s`: %w", u.DSN, err)
			return
		}
		tempUplink.name = u.Name
		if tempUplink.name == "" {
			tempUplink.name = details.Host
		}

		if !strings.Contains(details.Host, ":") {
			details.Host = fmt.Sprintf("%s:53", details.Host)
		}

		switch details.Scheme {
		case "tcp", "udp":
			if tempUplink.conn, err = net.DialTimeout(details.Scheme, details.Host, u.Timeout); err != nil {
				err = fmt.Errorf("failed connecting to upstream `%s`: %w", tempUplink.name, err)
				return
			}
		default:
			err = errors.New("unsupported protocol")
			return
		}

		tempUplink.client = dns.NewClient()

		r.uplinks = append(r.uplinks, tempUplink)
	}

	if len(r.uplinks) == 0 {
		err = errors.New("no uplinks")
	}

	return
}

// TODO implement failover and load balancing
func (r *Resolver) selectUplink() (uplink *Uplink) {
	return &r.uplinks[0]
}

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	u := r.selectUplink()

	if err = req.Unpack(); err != nil {
		req.Rcode = dns.RcodeFormatError
		err = fmt.Errorf("failed to unpack request: %w", err)
		return req, err
	}

	resp, _, err = u.client.ExchangeWithConn(ctx, req, u.conn)
	if err != nil || resp == nil {
		req.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("upstream `%s` failed: %w", u.name, err)
		return req, err
	}

	return
}

func (r *Resolver) Handle(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	resp, err := r.Resolve(ctx, req)
	if err != nil {
		log.L.Errorw("failed to resolve", "err", err)
		return
	}
	_, _ = resp.WriteTo(w)
}

func (r *Resolver) Close() (err error) {
	var errs []error
	for _, u := range r.uplinks {
		err = u.conn.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		err = errors.Join(errs...)
	}

	return
}
