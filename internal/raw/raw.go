// Package raw validates and describes MCT and NVRE raw-flash records.
package raw

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
)

const BlockSize = 65536

type Part struct {
	Name         string
	ID           byte
	Offset, Size int64
}
type Record struct {
	Name         string
	Offset, Size int64
}

func MCT(r binio.Reader, offset int64) ([]Part, error) {
	h, err := r.Bytes(offset, 8)
	if err != nil {
		return nil, err
	}
	if binio.U32(h, 0) != 0x92be564a || binio.LE.Uint16(h[6:]) != 1 {
		return nil, fmt.Errorf("invalid MCT header/version")
	}
	hash := crc32.NewIEEE()
	hash.Write(h)
	var parts []Part
	pos := offset + 8
	crcSeen, ended := false, false
	type rawPart struct {
		name        string
		id          byte
		first, last uint32
	}
	var rawParts []rawPart
	for n := 0; n < 32768; n++ {
		tlv, err := r.Bytes(pos, 2)
		if err != nil {
			return nil, err
		}
		if tlv[0] == 255 {
			ended = true
			break
		}
		length := int64(tlv[1])
		if length < 2 {
			return nil, fmt.Errorf("invalid MCT TLV length")
		}
		payload, err := r.Bytes(pos+2, length-2)
		if err != nil {
			return nil, err
		}
		if tlv[0] == 9 {
			if crcSeen || len(payload) < 6 {
				return nil, fmt.Errorf("invalid MCT CRC record")
			}
			if binio.U32(payload, 2) != hash.Sum32() {
				return nil, fmt.Errorf("MCT CRC mismatch")
			}
			crcSeen = true
		} else if crcSeen {
			return nil, fmt.Errorf("MCT data after CRC")
		}
		if tlv[0] == 0x39 {
			if len(payload) != 22 {
				return nil, fmt.Errorf("invalid MCT partition record")
			}
			name := string(bytes.TrimRight(payload[2:14], "\x00 "))
			if name == "" || strings.ContainsAny(name, "/\\:\x00") || name == "." || name == ".." {
				return nil, fmt.Errorf("unsafe MCT partition name")
			}
			first, last := binio.U32(payload, 14), binio.U32(payload, 18)
			if last < first {
				return nil, fmt.Errorf("reversed MCT partition")
			}
			rawParts = append(rawParts, rawPart{name, payload[0], first, last})
		}
		hash.Write(tlv)
		hash.Write(payload)
		pos += length
	}
	if !ended || !crcSeen {
		return nil, fmt.Errorf("MCT requires end marker and CRC")
	}
	var base int64 = -1
	for _, p := range rawParts {
		if strings.EqualFold(p.name, "nvram") {
			if base != -1 || p.first == 0 {
				return nil, fmt.Errorf("ambiguous/invalid NVRAM base")
			}
			base = (int64(p.first) - 1) * BlockSize
		}
	}
	if base < 0 {
		return nil, fmt.Errorf("MCT NVRAM partition required to determine raw-dump base")
	}
	for _, p := range rawParts {
		off := int64(p.first)*BlockSize - base
		size := (int64(p.last) - int64(p.first) + 1) * BlockSize
		if off < 0 {
			continue
		}
		if err = r.Range(off, size); err != nil {
			return nil, fmt.Errorf("partition %s is truncated: %w", p.name, err)
		}
		parts = append(parts, Part{p.name, p.id, off, size})
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("no readable partitions")
	}
	return parts, nil
}

// NVRE validates every record and skips wholly erased inter-record padding.
// Malformed records and checksum errors abort extraction instead of emitting a
// success result containing only whichever records happened to validate.
func NVRE(r binio.Reader) ([]Record, error) {
	var records []Record
	counts := map[string]int{}
	pos := int64(0)
	for pos < r.Size {
		if r.Size-pos < 32 {
			tail, err := r.Bytes(pos, r.Size-pos)
			if err != nil {
				return nil, err
			}
			if erased(tail) {
				break
			}
			return nil, fmt.Errorf("truncated NVRE record")
		}
		h, err := r.Bytes(pos, 28)
		if err != nil {
			return nil, err
		}
		if erased(h) {
			next := min((pos/BlockSize+1)*BlockSize, r.Size)
			padding, err := r.Bytes(pos, next-pos)
			if err != nil {
				return nil, err
			}
			if !erased(padding) {
				return nil, fmt.Errorf("non-erased NVRE padding at %d", pos)
			}
			pos = next
			continue
		}
		length, dataLen := int64(binio.U32(h, 16)), int64(binio.U32(h, 20))
		minimum := 28 + dataLen + 4
		if length < minimum || length > r.Size-pos {
			return nil, fmt.Errorf("invalid NVRE block length")
		}
		if err = r.Range(pos, minimum); err != nil {
			return nil, err
		}
		if crc32.ChecksumIEEE(h[:24]) != binio.U32(h, 24) {
			return nil, fmt.Errorf("NVRE header CRC mismatch at %d", pos)
		}
		magic, err := r.Bytes(pos+28+dataLen, 4)
		if err != nil {
			return nil, err
		}
		if string(magic) != "NVRE" {
			return nil, fmt.Errorf("NVRE footer missing")
		}
		hash := crc32.NewIEEE()
		if _, err = io.Copy(hash, io.NewSectionReader(r.ReaderAt, pos+28, dataLen)); err != nil {
			return nil, err
		}
		if hash.Sum32() != binio.U32(h, 8) {
			return nil, fmt.Errorf("NVRE data CRC mismatch at %d", pos)
		}
		key := fmt.Sprintf("%04X+%08X", binio.LE.Uint16(h[2:]), binio.U32(h, 4))
		counts[key]++
		name := key
		if counts[key] > 1 {
			name += fmt.Sprintf("_%d", counts[key])
		}
		records = append(records, Record{name + ".bin", pos + 28, dataLen})
		pos += length
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no NVRE records")
	}
	return records, nil
}
func erased(b []byte) bool {
	for _, v := range b {
		if v != 255 {
			return false
		}
	}
	return true
}
