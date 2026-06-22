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

	"github.com/k-danil/antizapret-go/server/router/matcher"
)

type Source struct {
	Name   string
	Action matcher.Action
	URI    string
	Parser Parser
	Filter *Filter
	Prune  bool
}

func (s *Source) GetReader(ctx context.Context) (r io.ReadCloser, err error) {
	var uri *url.URL
	if uri, err = url.Parse(s.URI); err != nil {
		err = fmt.Errorf("failed to parse uri `%s` source `%s`: %w", s.URI, s.Name, err)
		return
	}

	switch uri.Scheme {
	case "file":
		if r, err = os.Open(uri.Path); err != nil {
			err = fmt.Errorf("failed to open file `%s` for source `%s`: %w", uri.Path, s.Name, err)
			return
		}
	case "http", "https":
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil); err != nil {
			err = fmt.Errorf("failed to create request for source `%s`: %w", s.Name, err)
			return
		}
		var resp *http.Response
		if resp, err = http.DefaultClient.Do(req); err != nil {
			err = fmt.Errorf("failed to get response for source `%s`: %w", s.Name, err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			err = fmt.Errorf("source `%s`: unexpected status %s", s.Name, resp.Status)
			return
		}
		r = resp.Body
	default:
		err = fmt.Errorf("unsupported scheme `%s` for source `%s`", uri.Scheme, s.Name)
		return
	}

	return maybeGunzip(r)
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
