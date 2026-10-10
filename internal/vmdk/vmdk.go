// Package vmdk provides bounded flat/monolithic-sparse disk access.
package vmdk

import (
	"bytes"
	"fmt"
	"io"

	"github.com/bb10root/bb10mt/internal/binio"
)

const Sector = int64(512)

type Disk struct {
	R                         binio.Reader
	Size                      int64
	Sparse                    bool
	grain, entries, directory uint64
	flags                     uint32
}

func Open(r binio.Reader) (*Disk, error) {
	b, err := r.Bytes(0, min(r.Size, 512))
	if err != nil {
		return nil, err
	}
	d := &Disk{R: r, Size: r.Size}
	if len(b) < 4 || string(b[:4]) != "KDMV" {
		if r.Size < 512 || r.Size%512 != 0 {
			return nil, fmt.Errorf("flat disk must contain complete sectors")
		}
		return d, nil
	}
	if len(b) < 512 || binio.U32(b, 4) != 1 || binio.LE.Uint16(b[77:]) != 0 || binio.U32(b, 8)&0x30000 != 0 {
		return nil, fmt.Errorf("unsupported compressed/stream-optimized VMDK")
	}
	capacity := binio.U64(b, 12)
	d.grain = binio.U64(b, 20)
	d.entries = uint64(binio.U32(b, 44))
	d.directory = binio.U64(b, 56)
	d.flags = binio.U32(b, 8)
	if capacity == 0 || capacity > 1<<36 || d.grain == 0 || d.grain > 8192 || d.grain&(d.grain-1) != 0 || d.entries == 0 || d.entries > 65536 || d.directory == 0 || d.directory > uint64(r.Size)/512 {
		return nil, fmt.Errorf("invalid VMDK geometry")
	}
	count := (capacity + d.grain*d.entries - 1) / (d.grain * d.entries)
	if count > 1<<20 {
		return nil, fmt.Errorf("VMDK grain directory too large")
	}
	if err = r.Range(int64(d.directory)*512, int64(count)*4); err != nil {
		return nil, err
	}
	d.Size = int64(capacity) * 512
	d.Sparse = true
	return d, nil
}
func (d *Disk) physical(offset int64) (int64, int64, error) {
	if offset < 0 || offset >= d.Size {
		return 0, 0, io.EOF
	}
	if !d.Sparse {
		return offset, d.Size - offset, nil
	}
	grainBytes := int64(d.grain) * 512
	grainIndex := uint64(offset / grainBytes)
	within := offset % grainBytes
	gd, err := d.R.Bytes(int64(d.directory)*512+int64(grainIndex/d.entries)*4, 4)
	if err != nil {
		return 0, 0, err
	}
	gt := uint64(binio.U32(gd, 0))
	left := min(grainBytes-within, d.Size-offset)
	if gt == 0 {
		return -1, left, nil
	}
	if err = d.R.Range(int64(gt)*512, int64(d.entries)*4); err != nil {
		return 0, 0, err
	}
	entry, err := d.R.Bytes(int64(gt)*512+int64(grainIndex%d.entries)*4, 4)
	if err != nil {
		return 0, 0, err
	}
	n := uint64(binio.U32(entry, 0))
	if n == 0 || n == 1 && d.flags&4 != 0 {
		return -1, left, nil
	}
	physical := int64(n)*512 + within
	if err = d.R.Range(physical, left); err != nil {
		return 0, 0, err
	}
	return physical, left, nil
}
func (d *Disk) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative disk offset")
	}
	done := 0
	for done < len(p) {
		off, left, err := d.physical(offset)
		if err != nil {
			return done, err
		}
		n := min(int64(len(p)-done), left)
		if off < 0 {
			clear(p[done : done+int(n)])
		} else {
			got, err := d.R.ReadAt(p[done:done+int(n)], off)
			done += got
			offset += int64(got)
			if err != nil {
				return done, err
			}
			continue
		}
		done += int(n)
		offset += n
	}
	return done, nil
}

// WriteAt writes allocated grains only. A sparse hole can accept zeros; adding
// nonzero grains requires a layout-changing allocator and is rejected atomically
// by callers operating on a staged copy.
func (d *Disk) WriteAt(w io.WriterAt, p []byte, offset int64) (int, error) {
	if offset < 0 || int64(len(p)) > d.Size-offset {
		return 0, fmt.Errorf("disk write outside extent")
	}
	done := 0
	for done < len(p) {
		off, left, err := d.physical(offset)
		if err != nil {
			return done, err
		}
		n := min(int64(len(p)-done), left)
		part := p[done : done+int(n)]
		if off < 0 {
			if !bytes.Equal(part, make([]byte, len(part))) {
				return done, fmt.Errorf("cannot allocate an unmapped VMDK grain")
			}
		} else {
			got, err := w.WriteAt(part, off)
			done += got
			offset += int64(got)
			if err != nil {
				return done, err
			}
			if got != len(part) {
				return done, io.ErrShortWrite
			}
			continue
		}
		done += int(n)
		offset += n
	}
	return done, nil
}
