package resolver

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUpstream struct {
	fail      bool
	resp      *dns.Msg
	calls     int
	seenRcode []uint16
}

func (f *fakeUpstream) Resolve(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.calls++
	f.seenRcode = append(f.seenRcode, req.Rcode)
	if f.fail {
		return nil, errors.New("boom")
	}
	return f.resp, nil
}

func aQuery() *dns.Msg {
	return &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
}

// Регрессия: апстрим не должен мутировать запрос — иначе следующий по кругу
// апстрим получает query с Rcode=SERVFAIL в заголовке.
func TestResolveKeepsRequestCleanAcrossFailures(t *testing.T) {
	a := &fakeUpstream{fail: true}
	b := &fakeUpstream{fail: true}
	r := &Resolver{upstreams: []Upstream{a, b}}

	req := aQuery()
	resp, err := r.Resolve(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, resp)

	assert.EqualValues(t, dns.RcodeSuccess, req.Rcode, "request must stay unmutated after all upstreams fail")
	for _, f := range []*fakeUpstream{a, b} {
		require.Equal(t, 1, f.calls)
		assert.EqualValues(t, dns.RcodeSuccess, f.seenRcode[0], "every upstream must receive a clean query")
	}
}

func TestResolveFallsBackToWorkingUpstream(t *testing.T) {
	okResp := aQuery()
	okResp.Response = true

	bad := &fakeUpstream{fail: true}
	good := &fakeUpstream{resp: okResp}
	r := &Resolver{upstreams: []Upstream{bad, good}}

	resp, err := r.Resolve(context.Background(), aQuery())
	require.NoError(t, err)
	require.Same(t, okResp, resp)

	require.NotEmpty(t, good.seenRcode)
	assert.EqualValues(t, dns.RcodeSuccess, good.seenRcode[0], "working upstream must receive a clean query")
}
