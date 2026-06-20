package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

var (
	sourcesBucket = []byte("sources")
	errNotCached  = errors.New("source not cached")
)

type Store struct {
	db *bbolt.DB
}

func NewStore(path string) (s *Store, err error) {
	if dir := filepath.Dir(path); dir != "" {
		if err = os.MkdirAll(dir, 0o755); err != nil {
			err = fmt.Errorf("failed to create state dir `%s`: %w", dir, err)
			return
		}
	}

	var db *bbolt.DB
	if db, err = bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second}); err != nil {
		err = fmt.Errorf("failed to open state db `%s`: %w", path, err)
		return
	}

	if err = db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(sourcesBucket)
		return e
	}); err != nil {
		_ = db.Close()
		err = fmt.Errorf("failed to init state db: %w", err)
		return
	}

	return &Store{db: db}, nil
}

func (s *Store) Save(name string, entries []Entry) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(sourcesBucket).Put([]byte(name), encodeEntries(entries))
	})
}

func (s *Store) Load(name string) (entries []Entry, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(sourcesBucket).Get([]byte(name))
		if v == nil {
			return errNotCached
		}
		var e error
		entries, e = decodeEntries(v)
		return e
	})
	return
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Формат записи: [1 байт subdomains][2 байта BE длина домена][домен].
func encodeEntries(entries []Entry) []byte {
	buf := new(bytes.Buffer)
	var hdr [3]byte
	for _, e := range entries {
		if e.Subdomains {
			hdr[0] = 1
		} else {
			hdr[0] = 0
		}
		binary.BigEndian.PutUint16(hdr[1:], uint16(len(e.Domain)))
		buf.Write(hdr[:])
		buf.WriteString(e.Domain)
	}
	return buf.Bytes()
}

func decodeEntries(data []byte) (entries []Entry, err error) {
	r := bytes.NewReader(data)
	var hdr [3]byte
	for {
		if _, err = io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return entries, nil
			}
			return nil, fmt.Errorf("corrupt cache: %w", err)
		}
		domain := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
		if _, err = io.ReadFull(r, domain); err != nil {
			return nil, fmt.Errorf("corrupt cache: %w", err)
		}
		entries = append(entries, Entry{Domain: string(domain), Subdomains: hdr[0] == 1})
	}
}
