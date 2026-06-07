package router

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type Source struct {
	Name   string
	Action Action
	URI    string
	Parser Parser
	Filter *Filter
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
	}
	return
}
