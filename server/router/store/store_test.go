package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunRoundTrip(t *testing.T) {
	s, err := New(t.TempDir())
	require.NoError(t, err)

	v := Validator{ETag: "abc", MTime: 123, Size: 9, Fingerprint: "fp"}
	recs := []Record{
		{Key: []byte("com.a"), Mode: 2},
		{Key: []byte("com.b"), Mode: 1},
	}
	require.NoError(t, s.WriteRun("src-1", v, recs))

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
	require.Equal(t, recs, got)
}

func TestOpenRunMissing(t *testing.T) {
	s, _ := New(t.TempDir())
	_, _, err := s.OpenRun("nope")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestRetainRemovesOrphans(t *testing.T) {
	s, _ := New(t.TempDir())
	require.NoError(t, s.WriteRun("keep", Validator{}, nil))
	require.NoError(t, s.WriteRun("drop", Validator{}, nil))

	require.NoError(t, s.Retain([]string{"keep"}))

	_, r, err := s.OpenRun("keep")
	require.NoError(t, err)
	_ = r.Close()
	_, _, err = s.OpenRun("drop")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFSTRoundTrip(t *testing.T) {
	s, _ := New(t.TempDir())
	_, err := s.LoadFST()
	require.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, s.SaveFST([]byte("fstdata")))
	data, err := s.LoadFST()
	require.NoError(t, err)
	require.Equal(t, []byte("fstdata"), data)
}

func TestNewCleansStaleTemps(t *testing.T) {
	dir := t.TempDir()
	_, err := New(dir)
	require.NoError(t, err)

	stale := filepath.Join(dir, runsSubdir, "x.run.123"+tmpSuffix)
	require.NoError(t, os.WriteFile(stale, []byte("x"), 0o600))

	_, err = New(dir) // повторный New должен снести temp
	require.NoError(t, err)
	_, err = os.Stat(stale)
	require.True(t, os.IsNotExist(err))
}
