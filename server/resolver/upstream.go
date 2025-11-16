package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

type Upstream interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	io.Closer
}

type ClassicUpstream struct {
	name   string
	client *dns.Client
	conn   net.Conn
}

func NewClassicUpstream(name, dsn string, timeout time.Duration) (r *ClassicUpstream, err error) {
	r = new(ClassicUpstream)

	var details *url.URL
	details, err = url.Parse(dsn)
	if err != nil {
		err = fmt.Errorf("failed to parse upstream `%s`: %w", dsn, err)
		return
	}

	if name == "" {
		name = details.Host
	}
	r.name = name

	if !strings.Contains(details.Host, ":") {
		details.Host = fmt.Sprintf("%s:53", details.Host)
	}

	if r.conn, err = net.DialTimeout(details.Scheme, details.Host, timeout); err != nil {
		err = fmt.Errorf("failed connecting to upstream `%s`: %w", r.name, err)
		return
	}
	r.client = dns.NewClient()

	return
}

func (r *ClassicUpstream) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if err = req.Unpack(); err != nil {
		req.Rcode = dns.RcodeFormatError
		err = fmt.Errorf("failed to unpack request: %w", err)
		return req, err
	}

	resp, _, err = r.client.ExchangeWithConn(ctx, req, r.conn)
	if err != nil || resp == nil {
		req.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return req, err
	}

	return
}

func (r *ClassicUpstream) Close() error {
	return r.conn.Close()
}

type DoHUpstream struct {
	name   string
	url    string
	client *http.Client
}

func NewDoHUpstream(name, dsn string, timeout time.Duration) (r *DoHUpstream, err error) {
	return &DoHUpstream{name, dsn, &http.Client{Timeout: timeout}}, nil
}

func (r *DoHUpstream) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if err = req.Unpack(); err != nil {
		req.Rcode = dns.RcodeFormatError
		err = fmt.Errorf("failed to unpack request: %w", err)
		return req, err
	}

	var hreq *http.Request
	if hreq, err = dnshttp.NewRequest(http.MethodPost, r.url, req); err != nil {
		req.Rcode = dns.RcodeFormatError
		err = fmt.Errorf("failed to format DoH request: %w", err)
		return req, err
	}

	var hresp *http.Response
	if hresp, err = r.client.Do(hreq.WithContext(ctx)); err != nil {
		req.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return req, err
	}

	if resp, err = dnshttp.Response(hresp); err != nil || resp == nil {
		req.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return req, err
	}

	return
}

func (r *DoHUpstream) Close() error {
	return nil
}
