package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	runsSubdir = "runs"
	runSuffix  = ".run"
	tmpSuffix  = ".tmp"
	fstName    = "matcher.fst"
)

var ErrNotFound = errors.New("not found")

type Validator struct {
	ETag         string
	LastModified string
	MTime        int64
	Size         int64
	Fingerprint  string
}

type Record struct {
	Key  []byte
	Mode byte
}

type Store struct {
	dir     string
	runsDir string
}

func New(dir string) (s *Store, err error) {
	runsDir := filepath.Join(dir, runsSubdir)
	if err = os.MkdirAll(runsDir, 0o755); err != nil {
		err = fmt.Errorf("store: mkdir `%s`: %w", runsDir, err)
		return
	}
	s = &Store{dir: dir, runsDir: runsDir}
	s.cleanTemps()
	return
}

// хэш-суффикс — sanitize неинъективна, иначе разные имена дали бы один файл.
func runFile(name string) string {
	sum := sha256.Sum256([]byte(name))
	return sanitize(name) + "." + hex.EncodeToString(sum[:4]) + runSuffix
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "src"
	}
	return b.String()
}

func (s *Store) cleanTemps() {
	entries, err := os.ReadDir(s.runsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), tmpSuffix) {
			_ = os.Remove(filepath.Join(s.runsDir, e.Name()))
		}
	}
	_ = os.Remove(filepath.Join(s.dir, fstName+tmpSuffix))
}

// temp в той же дире — rename атомарен лишь внутри одной ФС.
func writeAtomic(path string, write func(io.Writer) error) (err error) {
	var tmp *os.File
	if tmp, err = os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*"+tmpSuffix); err != nil {
		return
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriter(tmp)
	if err = write(bw); err != nil {
		return
	}
	if err = bw.Flush(); err != nil {
		return
	}
	if err = tmp.Sync(); err != nil {
		return
	}
	if err = tmp.Close(); err != nil {
		return
	}
	return os.Rename(tmpName, path)
}

func (s *Store) WriteRun(name string, v Validator, recs []Record) error {
	path := filepath.Join(s.runsDir, runFile(name))
	return writeAtomic(path, func(w io.Writer) (err error) {
		if err = writePreamble(w); err != nil {
			return
		}
		if err = writeValidator(w, v); err != nil {
			return
		}
		return writeData(w, recs)
	})
}

type RunReader struct {
	f      *os.File
	br     *bufio.Reader
	remain uint32
}

func (s *Store) OpenRun(name string) (v Validator, r *RunReader, err error) {
	var f *os.File
	if f, err = os.Open(filepath.Join(s.runsDir, runFile(name))); err != nil {
		if os.IsNotExist(err) {
			err = ErrNotFound
		}
		return
	}

	br := bufio.NewReader(f)
	var dataLen uint32
	if v, dataLen, err = readHeader(br); err != nil {
		_ = f.Close()
		err = fmt.Errorf("store: run `%s`: %w", name, err)
		return
	}
	r = &RunReader{f: f, br: br, remain: dataLen}
	return
}

func (r *RunReader) Next() (rec Record, ok bool, err error) {
	if r.remain < recordHeaderLen {
		return
	}
	var rh [recordHeaderLen]byte
	if _, err = io.ReadFull(r.br, rh[:]); err != nil {
		return
	}
	keyLen := uint32(binary.BigEndian.Uint16(rh[1:]))
	r.remain -= recordHeaderLen
	if keyLen > r.remain {
		err = fmt.Errorf("store: truncated record")
		return
	}
	key := make([]byte, keyLen)
	if _, err = io.ReadFull(r.br, key); err != nil {
		return
	}
	r.remain -= keyLen
	rec = Record{Key: key, Mode: rh[0]}
	ok = true
	return
}

func (r *RunReader) Close() error { return r.f.Close() }

func (s *Store) LoadValidator(name string) (v Validator, err error) {
	var f *os.File
	if f, err = os.Open(filepath.Join(s.runsDir, runFile(name))); err != nil {
		if os.IsNotExist(err) {
			err = ErrNotFound
		}
		return
	}
	defer func() { _ = f.Close() }()
	v, _, err = readHeader(bufio.NewReader(f))
	return
}

func (s *Store) LoadFST() (data []byte, err error) {
	var raw []byte
	if raw, err = os.ReadFile(filepath.Join(s.dir, fstName)); err != nil {
		if os.IsNotExist(err) {
			err = ErrNotFound
		}
		return
	}
	return sectionValue(raw, secData)
}

func (s *Store) SaveFST(data []byte) error {
	return writeAtomic(filepath.Join(s.dir, fstName), func(w io.Writer) (err error) {
		if err = writePreamble(w); err != nil {
			return
		}
		return writeSection(w, secData, data)
	})
}

func (s *Store) Retain(names []string) (removed int, err error) {
	keep := make(map[string]struct{}, len(names))
	for _, n := range names {
		keep[runFile(n)] = struct{}{}
	}
	var entries []os.DirEntry
	if entries, err = os.ReadDir(s.runsDir); err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, tmpSuffix) {
			_ = os.Remove(filepath.Join(s.runsDir, n))
			continue
		}
		if _, ok := keep[n]; !ok && strings.HasSuffix(n, runSuffix) {
			if os.Remove(filepath.Join(s.runsDir, n)) == nil {
				removed++
			}
		}
	}
	return
}

func (s *Store) Close() error { return nil }
