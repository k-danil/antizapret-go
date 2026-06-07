package router

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGetReaderTransparentGunzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte("youtube.com\n#comment\nexample.org\n")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "list.txt.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	s := Source{Name: "g", URI: "file://" + path, Parser: PlainParser{subdomains: true}}
	rc, err := s.GetReader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()

	var domains []string
	if err = s.Parser.Parse(rc, func(e Entry) { domains = append(domains, e.Domain) }); err != nil {
		t.Fatal(err)
	}

	if len(domains) != 2 || domains[0] != "youtube.com" || domains[1] != "example.org" {
		t.Fatalf("gzip source not transparently decompressed, got %v", domains)
	}
}
