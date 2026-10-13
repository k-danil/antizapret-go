package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunRoundTrip(t *testing.T) {
	s, err := New(t.TempDir())
	require.NoError(t, err)

	v := Validator{ETag: "abc", MTime: 123, Size: 9, Fingerprint: "fp"}
	// вход не по порядку и с дублем: writeData сортирует и из дублей оставляет больший режим
	require.NoError(t, s.WriteRun("src-1", v, []Record{
		{Key: []byte("com.b"), Mode: 1},
		{Key: []byte("com.a"), Mode: 2},
		{Key: []byte("com.a"), Mode: 1},
	}))

	gotV, r, err := s.OpenRun("src-1")
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Equal(t, v, gotV)

	var got []Record
	for {
		rec, ok, e := r.Next()
		require.NoError(t, e)
		if !ok {
			break
		}
		got = append(got, Record{Key: append([]byte(nil), rec.Key...), Mode: rec.Mode})
	}
	require.Equal(t, []Record{
		{Key: []byte("com.a"), Mode: 2},
		{Key: []byte("com.b"), Mode: 1},
	}, got)
}
