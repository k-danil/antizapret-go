package store

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

const (
	magic            = "AZRS"
	formatVersion    = 1
	preambleLen      = len(magic) + 1
	sectionHeaderLen = 1 + 4 // type + length(BE u32)
	recordHeaderLen  = 1 + 2 // mode + keyLen(BE u16)
)

// Типы секций: 1–15 — поля валидатора (с запасом на новые), 16+ — payload/служебные.
const (
	secETag = 1 + iota
	secLastModified
	secMTime
	secSize
	secFingerprint
	secData = 16
)

var errBadFormat = errors.New("not an AZRS store file")

func writePreamble(w io.Writer) (err error) {
	if _, err = io.WriteString(w, magic); err != nil {
		return
	}
	_, err = w.Write([]byte{formatVersion})
	return
}

func writeSection(w io.Writer, typ byte, value []byte) (err error) {
	var h [sectionHeaderLen]byte
	h[0] = typ
	binary.BigEndian.PutUint32(h[1:], uint32(len(value)))
	if _, err = w.Write(h[:]); err != nil {
		return
	}
	_, err = w.Write(value)
	return
}

func writeValidator(w io.Writer, v Validator) (err error) {
	str := func(typ byte, s string) error {
		if s == "" {
			return nil
		}
		return writeSection(w, typ, []byte(s))
	}
	num := func(typ byte, n int64) error {
		if n == 0 {
			return nil
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		return writeSection(w, typ, b[:])
	}
	if err = str(secETag, v.ETag); err != nil {
		return
	}
	if err = str(secLastModified, v.LastModified); err != nil {
		return
	}
	if err = num(secMTime, v.MTime); err != nil {
		return
	}
	if err = num(secSize, v.Size); err != nil {
		return
	}
	return str(secFingerprint, v.Fingerprint)
}

func writeData(w io.Writer, recs []Record) (err error) {
	slices.SortFunc(recs, func(a, b Record) int { return bytes.Compare(a.Key, b.Key) })

	dataLen := 0
	for _, r := range recs {
		dataLen += recordHeaderLen + len(r.Key)
	}
	var sh [sectionHeaderLen]byte
	sh[0] = secData
	binary.BigEndian.PutUint32(sh[1:], uint32(dataLen))
	if _, err = w.Write(sh[:]); err != nil {
		return
	}
	var rh [recordHeaderLen]byte
	for _, r := range recs {
		rh[0] = r.Mode
		binary.BigEndian.PutUint16(rh[1:], uint16(len(r.Key)))
		if _, err = w.Write(rh[:]); err != nil {
			return
		}
		if _, err = w.Write(r.Key); err != nil {
			return
		}
	}
	return
}

func readPreamble(br *bufio.Reader) error {
	var p [preambleLen]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return errBadFormat
	}
	if string(p[:len(magic)]) != magic {
		return errBadFormat
	}
	if p[len(magic)] != formatVersion {
		return fmt.Errorf("store: unsupported format version %d", p[len(magic)])
	}
	return nil
}

func readSectionHeader(br *bufio.Reader) (typ byte, length uint32, err error) {
	var h [sectionHeaderLen]byte
	if _, err = io.ReadFull(br, h[:]); err != nil {
		return
	}
	return h[0], binary.BigEndian.Uint32(h[1:]), nil
}

// readHeader оставляет br на записях DATA; dataLen — их суммарная длина.
func readHeader(br *bufio.Reader) (v Validator, dataLen uint32, err error) {
	if err = readPreamble(br); err != nil {
		return
	}
	for {
		var typ byte
		var length uint32
		if typ, length, err = readSectionHeader(br); err != nil {
			return
		}
		if typ == secData {
			dataLen = length
			return
		}
		val := make([]byte, length)
		if _, err = io.ReadFull(br, val); err != nil {
			return
		}
		switch typ {
		case secETag:
			v.ETag = string(val)
		case secLastModified:
			v.LastModified = string(val)
		case secMTime:
			if len(val) == 8 {
				v.MTime = int64(binary.BigEndian.Uint64(val))
			}
		case secSize:
			if len(val) == 8 {
				v.Size = int64(binary.BigEndian.Uint64(val))
			}
		case secFingerprint:
			v.Fingerprint = string(val)
		default:
			// неизвестный type — скип ради forward-compat
		}
	}
}

func sectionValue(raw []byte, want byte) ([]byte, error) {
	if len(raw) < preambleLen || string(raw[:len(magic)]) != magic {
		return nil, errBadFormat
	}
	if raw[len(magic)] != formatVersion {
		return nil, fmt.Errorf("store: unsupported format version %d", raw[len(magic)])
	}
	for p := preambleLen; p+sectionHeaderLen <= len(raw); {
		typ := raw[p]
		length := int(binary.BigEndian.Uint32(raw[p+1:]))
		p += sectionHeaderLen
		if p+length > len(raw) {
			return nil, fmt.Errorf("store: truncated section")
		}
		if typ == want {
			return raw[p : p+length], nil
		}
		p += length
	}
	return nil, ErrNotFound
}
