package resolver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

type Upstream interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type ClassicUpstream struct {
	name         string
	client       *dns.Client
	schema, host string
	timeout      time.Duration
}

func NewClassicUpstream(name, dsn string, timeout time.Duration) (r *ClassicUpstream, err error) {
	var details *url.URL
	details, err = url.Parse(dsn)
	if err != nil {
		err = fmt.Errorf("failed to parse upstream `%s`: %w", dsn, err)
		return
	}

	r = &ClassicUpstream{
		name:    name,
		schema:  details.Scheme,
		host:    details.Host,
		timeout: timeout,
		client:  dns.NewClient(),
	}

	if !strings.Contains(r.host, ":") {
		r.host = fmt.Sprintf("%s:53", r.host)
	}

	if r.name == "" {
		r.name = r.host
	}

	return
}

func (r *ClassicUpstream) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	resp, _, err = r.client.Exchange(ctx, req, r.schema, r.host)
	if err != nil || resp == nil {
		req.Rcode = dns.RcodeServerFailure
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return req, err
	}

	return
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
