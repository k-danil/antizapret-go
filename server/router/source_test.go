package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/k-danil/antizapret-go/server/router/store"
	"github.com/stretchr/testify/require"
)

func TestFetchTransparentGunzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte("youtube.com\n#comment\nexample.org\n"))
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	path := filepath.Join(t.TempDir(), "list.txt.gz")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	res, err := fileFetcher{path: path}.fetch(context.Background(), store.Validator{})
	require.NoError(t, err)
	require.False(t, res.NotModified)
	defer func() { _ = res.Reader.Close() }()

	var domains []string
	require.NoError(t, PlainParser{subdomains: true}.Parse(res.Reader, func(e Entry) { domains = append(domains, e.Domain) }))

	require.Equal(t, []string{"youtube.com", "example.org"}, domains, "gzip-источник распакован прозрачно")
}

func TestFetchHTTPConditional(t *testing.T) {
	const etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, "a.com\n")
	}))
	defer srv.Close()

	hf := httpFetcher{uri: srv.URL}

	res, err := hf.fetch(context.Background(), store.Validator{})
	require.NoError(t, err)
	require.False(t, res.NotModified)
	require.Equal(t, etag, res.Validator.ETag)
	_ = res.Reader.Close()

	res, err = hf.fetch(context.Background(), store.Validator{ETag: etag})
	require.NoError(t, err)
	require.True(t, res.NotModified, "If-None-Match совпал → 304")
}
