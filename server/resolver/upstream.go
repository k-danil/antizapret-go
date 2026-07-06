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

const (
	schemaUDP = "udp"
	schemaTCP = "tcp"
)

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

	if resp, _, err = r.client.Exchange(ctx, req, r.schema, r.host); err != nil {
		resp = nil
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return
	}
	if resp == nil {
		err = fmt.Errorf("upstream `%s` returned no response", r.name)
		return
	}

	if resp.Truncated && strings.HasPrefix(r.schema, schemaUDP) {
		resp, err = r.retryTCP(ctx, req)
	}

	return
}

// client.Exchange при TC-бите TCP-фоллбэка не делает. Копия с Data=nil обязательна:
// Exchange читает ответ в алиас req.Data, повторная отправка затёртого буфера ушла бы мусором.
func (r *ClassicUpstream) retryTCP(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	tcpReq := req.Copy()
	tcpReq.Data = nil

	network := strings.Replace(r.schema, schemaUDP, schemaTCP, 1)
	if resp, _, err = r.client.Exchange(ctx, tcpReq, network, r.host); err != nil {
		resp = nil
		err = fmt.Errorf("upstream `%s` tcp retry after truncation failed: %w", r.name, err)
		return
	}
	if resp == nil {
		err = fmt.Errorf("upstream `%s` returned no response on tcp retry", r.name)
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
		err = fmt.Errorf("failed to format DoH request: %w", err)
		return
	}

	var hresp *http.Response
	if hresp, err = r.client.Do(hreq.WithContext(ctx)); err != nil {
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return
	}

	if resp, err = dnshttp.Response(hresp); err != nil {
		resp = nil
		err = fmt.Errorf("upstream `%s` failed: %w", r.name, err)
		return
	}
	if resp == nil {
		err = fmt.Errorf("upstream `%s` returned no response", r.name)
	}

	return
}
