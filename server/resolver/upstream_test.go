package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/stretchr/testify/require"
)

const upstreamTestTimeout = 3 * time.Second

func startTruncatingUDP(t *testing.T) (addr string, hits *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	hits = new(atomic.Int32)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			hits.Add(1)
			req := &dns.Msg{Data: append([]byte(nil), buf[:n]...)}
			if req.Unpack() != nil {
				continue
			}
			resp := req.Copy()
			resp.Data = nil
			resp.Response = true
			resp.Truncated = true
			if resp.Pack() != nil {
				continue
			}
			_, _ = pc.WriteTo(resp.Data, raddr)
		}
	}()
	return pc.LocalAddr().String(), hits
}

func startFullTCP(t *testing.T, addr string) (hits *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	hits = new(atomic.Int32)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			hits.Add(1)
			go serveFullTCPConn(conn)
		}
	}()
	return hits
}

func serveFullTCPConn(c net.Conn) {
	defer func() { _ = c.Close() }()

	var l uint16
	if binary.Read(c, binary.BigEndian, &l) != nil {
		return
	}
	data := make([]byte, l)
	if _, err := io.ReadFull(c, data); err != nil {
		return
	}
	req := &dns.Msg{Data: data}
	if req.Unpack() != nil {
		return
	}

	resp := req.Copy()
	resp.Data = nil
	resp.Response = true
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60}}
	a.Addr = netip.AddrFrom4([4]byte{1, 2, 3, 4})
	resp.Answer = []dns.RR{a}
	if resp.Pack() != nil {
		return
	}

	buf := make([]byte, 2, 2+len(resp.Data))
	binary.BigEndian.PutUint16(buf, uint16(len(resp.Data)))
	buf = append(buf, resp.Data...)
	_, _ = c.Write(buf)
}

func TestClassicUpstreamTCPFallbackOnTruncation(t *testing.T) {
	addr, udpHits := startTruncatingUDP(t)
	tcpHits := startFullTCP(t, addr)

	up, err := NewClassicUpstream("test", "udp://"+addr, upstreamTestTimeout)
	require.NoError(t, err)

	resp, err := up.Resolve(context.Background(), aQuery())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.Truncated, "фоллбэк должен вернуть полный TCP-ответ")
	require.Len(t, resp.Answer, 1)
	require.EqualValues(t, 1, udpHits.Load())
	require.EqualValues(t, 1, tcpHits.Load())
}

func TestClassicUpstreamTCPFallbackFailureIsError(t *testing.T) {
	addr, _ := startTruncatingUDP(t) // TCP на этом порту никто не слушает

	up, err := NewClassicUpstream("test", "udp://"+addr, upstreamTestTimeout)
	require.NoError(t, err)

	resp, err := up.Resolve(context.Background(), aQuery())
	require.Error(t, err, "усечённый ответ не должен сходить за успех")
	require.Nil(t, resp)
}
