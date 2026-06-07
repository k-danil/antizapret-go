package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/cfg"
	rtr "github.com/antizapret-vpn/go-proxy/server/router"
)

// captureWriter — минимальный dns.ResponseWriter, складывающий записанные байты.
type captureWriter struct{ buf []byte }

func (c *captureWriter) Write(b []byte) (int, error) { c.buf = append(c.buf, b...); return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) LocalAddr() net.Addr         { return nil }
func (c *captureWriter) RemoteAddr() net.Addr        { return nil }
func (c *captureWriter) Conn() net.Conn              { return nil }
func (c *captureWriter) Session() *dns.Session       { return nil }
func (c *captureWriter) Hijack()                     {}

func remapServer(t *testing.T, domain string) *Server {
	t.Helper()
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(listPath, []byte(domain), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := rtr.NewStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	r, err := rtr.NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + listPath, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &Server{router: r, timeout: time.Second}
}

func typedQuery(name string, rr dns.RR) *dns.Msg {
	rr.Header().Name = name
	rr.Header().Class = dns.ClassINET
	return &dns.Msg{Question: []dns.RR{rr}}
}

func TestDNSHandlerSuppressesHTTPSAndSVCBForRemap(t *testing.T) {
	s := remapServer(t, "blocked.test")

	for _, q := range []dns.RR{&dns.HTTPS{}, &dns.SVCB{}} {
		w := &captureWriter{}
		s.DNSHandler(context.Background(), w, typedQuery("blocked.test.", q))

		if len(w.buf) < 2 {
			t.Fatalf("%T: nothing written", q)
		}
		parsed := &dns.Msg{Data: w.buf[2:]} // снять 2-байтовый префикс длины
		if err := parsed.Unpack(); err != nil {
			t.Fatalf("%T: unpack reply: %v", q, err)
		}

		if !parsed.Response {
			t.Fatalf("%T: reply must have QR bit set (got echoed query?)", q)
		}
		if parsed.Rcode != dns.RcodeSuccess {
			t.Fatalf("%T: rcode = %d, want NOERROR", q, parsed.Rcode)
		}
		if len(parsed.Answer) != 0 {
			t.Fatalf("%T: answer must be empty (NODATA), got %d records", q, len(parsed.Answer))
		}
	}
}
