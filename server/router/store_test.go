package router

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]Entry{
		nil,
		{{Domain: "example.com", Subdomains: true}},
		{{Domain: "a.test", Subdomains: false}, {Domain: "xn--80ak6aa92e.com", Subdomains: true}},
	}
	for _, in := range cases {
		out, err := decodeEntries(encodeEntries(in))
		require.NoError(t, err)
		require.Equal(t, in, out, "round-trip")
	}
}

func TestDecodeCorrupt(t *testing.T) {
	// заголовок заявляет домен длиной 5, но данных нет
	_, err := decodeEntries([]byte{1, 0, 5})
	require.Error(t, err, "усечённая запись должна дать ошибку")
}

func TestStoreSaveLoad(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	entries := []Entry{{Domain: "a.test", Subdomains: true}, {Domain: "b.test", Subdomains: false}}
	require.NoError(t, s.Save("src", entries))

	got, err := s.Load("src")
	require.NoError(t, err)
	require.Equal(t, entries, got)

	_, err = s.Load("missing")
	require.ErrorIs(t, err, errNotCached)
}
