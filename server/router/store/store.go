package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lm,omitempty"`
	MTime        int64  `json:"mtime,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Fingerprint  string `json:"fp,omitempty"`
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
		return nil, fmt.Errorf("store: mkdir `%s`: %w", runsDir, err)
	}
	s = &Store{dir: dir, runsDir: runsDir}
	s.cleanTemps()
	return s, nil
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
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*"+tmpSuffix)
	if err != nil {
		return err
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
		return err
	}
	if err = bw.Flush(); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Store) WriteRun(name string, v Validator, recs []Record) error {
	slices.SortFunc(recs, func(a, b Record) int { return bytes.Compare(a.Key, b.Key) })
	path := filepath.Join(s.runsDir, runFile(name))
	return writeAtomic(path, func(w io.Writer) error {
		hdr, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var u [4]byte
		binary.BigEndian.PutUint32(u[:], uint32(len(hdr)))
		if _, err = w.Write(u[:]); err != nil {
			return err
		}
		if _, err = w.Write(hdr); err != nil {
			return err
		}
		var rh [3]byte
		for _, r := range recs {
			rh[0] = r.Mode
			binary.BigEndian.PutUint16(rh[1:], uint16(len(r.Key)))
			if _, err = w.Write(rh[:]); err != nil {
				return err
			}
			if _, err = w.Write(r.Key); err != nil {
				return err
			}
		}
		return nil
	})
}

type RunReader struct {
	f  *os.File
	br *bufio.Reader
}

func (s *Store) OpenRun(name string) (v Validator, r *RunReader, err error) {
	f, err := os.Open(filepath.Join(s.runsDir, runFile(name)))
	if err != nil {
		if os.IsNotExist(err) {
			err = ErrNotFound
		}
		return Validator{}, nil, err
	}
	br := bufio.NewReader(f)

	var u [4]byte
	if _, err = io.ReadFull(br, u[:]); err != nil {
		_ = f.Close()
		return Validator{}, nil, fmt.Errorf("store: run `%s` header: %w", name, err)
	}
	hdr := make([]byte, binary.BigEndian.Uint32(u[:]))
	if _, err = io.ReadFull(br, hdr); err != nil {
		_ = f.Close()
		return Validator{}, nil, fmt.Errorf("store: run `%s` header: %w", name, err)
	}
	if err = json.Unmarshal(hdr, &v); err != nil {
		_ = f.Close()
		return Validator{}, nil, fmt.Errorf("store: run `%s` header: %w", name, err)
	}
	return v, &RunReader{f: f, br: br}, nil
}

func (r *RunReader) Next() (rec Record, ok bool, err error) {
	var rh [3]byte
	if _, err = io.ReadFull(r.br, rh[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	key := make([]byte, binary.BigEndian.Uint16(rh[1:]))
	if _, err = io.ReadFull(r.br, key); err != nil {
		return Record{}, false, err
	}
	return Record{Key: key, Mode: rh[0]}, true, nil
}

func (r *RunReader) Close() error { return r.f.Close() }

func (s *Store) HasRun(name string) bool {
	_, err := os.Stat(filepath.Join(s.runsDir, runFile(name)))
	return err == nil
}

func (s *Store) LoadFST() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, fstName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

func (s *Store) SaveFST(data []byte) error {
	return writeAtomic(filepath.Join(s.dir, fstName), func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func (s *Store) Retain(names []string) error {
	keep := make(map[string]struct{}, len(names))
	for _, n := range names {
		keep[runFile(n)] = struct{}{}
	}
	entries, err := os.ReadDir(s.runsDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, tmpSuffix) {
			_ = os.Remove(filepath.Join(s.runsDir, n))
			continue
		}
		if _, ok := keep[n]; !ok && strings.HasSuffix(n, runSuffix) {
			_ = os.Remove(filepath.Join(s.runsDir, n))
		}
	}
	return nil
}

func (s *Store) Close() error { return nil }
