package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetReaderTransparentGunzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte("youtube.com\n#comment\nexample.org\n"))
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	path := filepath.Join(t.TempDir(), "list.txt.gz")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	s := Source{Name: "g", URI: "file://" + path, Parser: PlainParser{subdomains: true}}
	rc, err := s.GetReader(context.Background())
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	var domains []string
	require.NoError(t, s.Parser.Parse(rc, func(e Entry) { domains = append(domains, e.Domain) }))

	require.Equal(t, []string{"youtube.com", "example.org"}, domains, "gzip-источник распакован прозрачно")
}
