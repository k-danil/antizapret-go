package store

import (
	"bytes"
	"encoding/binary"
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

	removed, err := s.Retain([]string{"keep"})
	require.NoError(t, err)
	require.Equal(t, 1, removed)

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

func TestOpenRunRejectsForeignOrFutureFormat(t *testing.T) {
	s, _ := New(t.TempDir())
	write := func(name string, data []byte) {
		require.NoError(t, os.WriteFile(filepath.Join(s.runsDir, runFile(name)), data, 0o600))
	}

	write("garbage", []byte("not-azrs-at-all"))
	_, _, err := s.OpenRun("garbage")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNotFound) // присутствует, но битый — это не «нет файла»

	write("future", append([]byte(magic), formatVersion+1))
	_, _, err = s.OpenRun("future")
	require.Error(t, err)
}

func TestOpenRunSkipsUnknownSection(t *testing.T) {
	s, _ := New(t.TempDir())

	var buf bytes.Buffer
	require.NoError(t, writePreamble(&buf))
	require.NoError(t, writeSection(&buf, secETag, []byte("tag")))
	require.NoError(t, writeSection(&buf, 99, []byte("из будущего"))) // unknown → должен скипнуться

	rec := Record{Key: []byte("com.x"), Mode: 2}
	var sh [sectionHeaderLen]byte
	sh[0] = secData
	binary.BigEndian.PutUint32(sh[1:], uint32(recordHeaderLen+len(rec.Key)))
	buf.Write(sh[:])
	var rh [recordHeaderLen]byte
	rh[0] = rec.Mode
	binary.BigEndian.PutUint16(rh[1:], uint16(len(rec.Key)))
	buf.Write(rh[:])
	buf.Write(rec.Key)

	require.NoError(t, os.WriteFile(filepath.Join(s.runsDir, runFile("x")), buf.Bytes(), 0o600))

	v, r, err := s.OpenRun("x")
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Equal(t, "tag", v.ETag) // валидатор прочитан, несмотря на чужую секцию между ним и DATA

	got, ok, err := r.Next()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, rec, Record{Key: append([]byte(nil), got.Key...), Mode: got.Mode})

	_, ok, err = r.Next()
	require.NoError(t, err)
	require.False(t, ok)
}
