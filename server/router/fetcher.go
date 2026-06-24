package router

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/k-danil/antizapret-go/server/router/store"
)

type FetchResult struct {
	NotModified bool
	Validator   store.Validator
	Reader      io.ReadCloser
}

type fetcher interface {
	fetch(ctx context.Context, prev store.Validator) (FetchResult, error)
}

func newFetcher(uri string) (fetcher, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parse uri `%s`: %w", uri, err)
	}
	switch u.Scheme {
	case "file":
		return fileFetcher{path: u.Path}, nil
	case "http", "https":
		return httpFetcher{uri: u.String()}, nil
	default:
		return nil, fmt.Errorf("unsupported scheme `%s`", u.Scheme)
	}
}

type fileFetcher struct{ path string }

func (f fileFetcher) fetch(_ context.Context, prev store.Validator) (res FetchResult, err error) {
	var info os.FileInfo
	if info, err = os.Stat(f.path); err != nil {
		err = fmt.Errorf("stat file `%s`: %w", f.path, err)
		return
	}
	mtime, size := info.ModTime().UnixNano(), info.Size()
	if prev.MTime == mtime && prev.Size == size {
		res.NotModified = true
		return
	}

	var file *os.File
	if file, err = os.Open(f.path); err != nil {
		err = fmt.Errorf("open file `%s`: %w", f.path, err)
		return
	}
	if res.Reader, err = maybeGunzip(file); err != nil {
		return
	}
	res.Validator = store.Validator{MTime: mtime, Size: size}
	return
}

type httpFetcher struct{ uri string }

func (h httpFetcher) fetch(ctx context.Context, prev store.Validator) (res FetchResult, err error) {
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, h.uri, nil); err != nil {
		err = fmt.Errorf("create request: %w", err)
		return
	}
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	var resp *http.Response
	if resp, err = http.DefaultClient.Do(req); err != nil {
		err = fmt.Errorf("get response: %w", err)
		return
	}
	if resp.StatusCode == http.StatusNotModified {
		_ = resp.Body.Close()
		res.NotModified = true
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		err = fmt.Errorf("unexpected status %s", resp.Status)
		return
	}

	if res.Reader, err = maybeGunzip(resp.Body); err != nil {
		return
	}
	res.Validator = store.Validator{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	return
}

type multiCloserReader struct {
	io.Reader
	closers []io.Closer
}

func (m multiCloserReader) Close() error {
	var errs []error
	for _, c := range m.closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func maybeGunzip(raw io.ReadCloser) (io.ReadCloser, error) {
	br := bufio.NewReader(raw)
	magic, _ := br.Peek(2)
	if len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
		return multiCloserReader{Reader: br, closers: []io.Closer{raw}}, nil
	}

	gz, err := gzip.NewReader(br)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gzip: %w", err)
	}
	return multiCloserReader{Reader: gz, closers: []io.Closer{gz, raw}}, nil
}
