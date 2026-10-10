// Package rcfs reads BB10 RCFS inode trees and verifies packed VSIG hashes.
package rcfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/woozymasta/lzo"
)

const chunkSize = 16384

type Node struct {
	Index          uint32 `json:"inode"`
	Name           string `json:"name"`
	Mode, Extended uint16
	Offset, Size   uint32
	Raw            []byte `json:"-"`
}
type Verification struct {
	Index, PackedSize uint32
	Hash              [32]byte
	Offset            int64
}
type Image struct {
	R                                                                binio.Reader
	InodeOffset, Count, NamesOffset, NamesSize, DataOffset, DataSize uint32
	Verifier                                                         Node
	Hashes                                                           map[uint32]Verification
}

func Open(r binio.Reader) (*Image, error) {
	header, err := r.Bytes(0, 88)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != "rimh" || binio.U32(header, 4) != 2 {
		return nil, fmt.Errorf("unsupported RCFS header")
	}
	s, err := r.Bytes(4096, 80)
	if err != nil {
		return nil, err
	}
	if string(s[32:40]) != "r-c-f-s\x00" {
		return nil, fmt.Errorf("invalid RCFS superblock")
	}
	im := &Image{R: r, Count: binio.U32(s, 52), InodeOffset: binio.U32(s, 56), NamesOffset: binio.U32(s, 64), NamesSize: binio.U32(s, 68), DataOffset: binio.U32(s, 72), DataSize: binio.U32(s, 76), Hashes: map[uint32]Verification{}}
	if im.Count == 0 || im.Count > 1<<20 || uint64(im.Count)*32 > uint64(binio.U32(s, 60)) {
		return nil, fmt.Errorf("invalid RCFS inode count")
	}
	for _, v := range [][2]uint32{{im.InodeOffset, binio.U32(s, 60)}, {im.NamesOffset, im.NamesSize}, {im.DataOffset, im.DataSize}} {
		if err = r.Range(int64(v[0]), int64(v[1])); err != nil {
			return nil, err
		}
	}
	if uint64(binio.U32(s, 48)) > uint64(r.Size) {
		return nil, fmt.Errorf("truncated RCFS image")
	}
	verifier, err := im.Resolve("/verifier.log")
	if err != nil {
		return nil, fmt.Errorf("RCFS verifier: %w", err)
	}
	if verifier.Extended>>7 != 0 || verifier.Mode&0xf000 != 0x8000 {
		return nil, fmt.Errorf("unsupported compressed verifier")
	}
	im.Verifier = verifier
	vh, err := r.Bytes(int64(verifier.Offset), 12)
	if err != nil {
		return nil, err
	}
	if string(vh[:4]) != "VSIG" {
		return nil, fmt.Errorf("invalid VSIG header")
	}
	n := uint64(binio.U32(vh, 4)) + uint64(binio.U32(vh, 8))
	if n > uint64(im.Count) || n*48+12 > uint64(verifier.Size) {
		return nil, fmt.Errorf("VSIG table exceeds verifier")
	}
	rows, err := r.Bytes(int64(verifier.Offset)+12, int64(n)*48)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		row := rows[i*48 : (i+1)*48]
		index := binio.U32(row, 0)
		if index < 1 || index > im.Count {
			return nil, fmt.Errorf("VSIG inode out of range")
		}
		if _, ok := im.Hashes[index]; ok {
			return nil, fmt.Errorf("duplicate VSIG inode")
		}
		v := Verification{Index: index, PackedSize: binio.U32(row, 8), Offset: int64(verifier.Offset) + 12 + int64(i)*48}
		copy(v.Hash[:], row[12:44])
		im.Hashes[index] = v
	}
	return im, nil
}
func (im *Image) Node(index uint32) (Node, error) {
	var n Node
	if index < 1 || index > im.Count {
		return n, fmt.Errorf("RCFS inode out of range")
	}
	b, err := im.R.Bytes(int64(im.InodeOffset)+int64(index-1)*32, 32)
	if err != nil {
		return n, err
	}
	n = Node{Index: index, Mode: binio.LE.Uint16(b[4:]), Extended: binio.LE.Uint16(b[6:]), Offset: binio.U32(b, 12), Size: binio.U32(b, 16), Raw: b}
	name := binio.U32(b, 8)
	if name < im.NamesOffset || uint64(name) >= uint64(im.NamesOffset)+uint64(im.NamesSize) {
		return n, fmt.Errorf("RCFS name outside table")
	}
	str, err := im.R.Bytes(int64(name), min(1024, int64(im.NamesOffset)+int64(im.NamesSize)-int64(name)))
	if err != nil {
		return n, err
	}
	end := bytes.IndexByte(str, 0)
	if end < 0 {
		return n, fmt.Errorf("unterminated RCFS name")
	}
	n.Name = string(str[:end])
	if strings.ContainsAny(n.Name, "/\\\x00") || n.Name == "." || n.Name == ".." || n.Name == "" && index != 1 {
		return n, fmt.Errorf("unsafe RCFS name")
	}
	return n, nil
}
func (im *Image) Children(n Node) ([]Node, error) {
	if n.Mode&0xf000 != 0x4000 {
		return nil, fmt.Errorf("RCFS inode is not directory")
	}
	if n.Size == 0 {
		return nil, nil
	}
	if n.Offset < im.InodeOffset || (n.Offset-im.InodeOffset)%32 != 0 || n.Size%32 != 0 {
		return nil, fmt.Errorf("invalid RCFS directory extent")
	}
	first := (n.Offset-im.InodeOffset)/32 + 1
	count := n.Size / 32
	if uint64(first)+uint64(count) > uint64(im.Count)+1 {
		return nil, fmt.Errorf("RCFS directory exceeds inode table")
	}
	rows := make([]Node, 0, count)
	names := map[string]bool{}
	for i := uint32(0); i < count; i++ {
		child, err := im.Node(first + i)
		if err != nil {
			return nil, err
		}
		if names[child.Name] {
			return nil, fmt.Errorf("duplicate RCFS pathname")
		}
		names[child.Name] = true
		rows = append(rows, child)
	}
	return rows, nil
}
func (im *Image) Resolve(p string) (Node, error) {
	n, err := im.Node(1)
	if err != nil {
		return n, err
	}
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			return n, fmt.Errorf("noncanonical RCFS path")
		}
		children, err := im.Children(n)
		if err != nil {
			return n, err
		}
		found := false
		for _, child := range children {
			if child.Name == part {
				n = child
				found = true
				break
			}
		}
		if !found {
			return n, fmt.Errorf("RCFS path missing: %s", p)
		}
	}
	return n, nil
}
func (im *Image) offsets(n Node) ([]uint32, error) {
	if n.Size == 0 {
		return nil, nil
	}
	first, err := im.R.Bytes(int64(n.Offset), 4)
	if err != nil {
		return nil, err
	}
	size := binio.U32(first, 0)
	expected := (uint64(n.Size) + chunkSize - 1) / chunkSize
	if size%4 != 0 || size < 8 || uint64(size)/4 > expected+3 {
		return nil, fmt.Errorf("invalid LZO chunk table")
	}
	b, err := im.R.Bytes(int64(n.Offset), int64(size))
	if err != nil {
		return nil, err
	}
	var offsets []uint32
	for p := 0; p < len(b); p += 4 {
		v := binio.U32(b, p)
		if v == 0 && len(offsets) > 0 {
			for q := p; q < len(b); q++ {
				if b[q] != 0 {
					return nil, fmt.Errorf("invalid chunk table padding")
				}
			}
			break
		}
		if len(offsets) > 0 && (v <= offsets[len(offsets)-1] || v-offsets[len(offsets)-1] > chunkSize+2048) {
			return nil, fmt.Errorf("invalid LZO chunk interval")
		}
		offsets = append(offsets, v)
	}
	if len(offsets) != int(expected)+1 {
		return nil, fmt.Errorf("LZO chunk count disagrees with inode size")
	}
	if err = im.R.Range(int64(n.Offset), int64(offsets[len(offsets)-1])); err != nil {
		return nil, err
	}
	return offsets, nil
}
func (im *Image) PackedSize(n Node) (uint32, error) {
	if n.Size == 0 {
		return 0, nil
	}
	if n.Extended>>7 == 0 {
		return n.Size, im.R.Range(int64(n.Offset), int64(n.Size))
	}
	if n.Extended>>7 != 1 {
		return 0, fmt.Errorf("unsupported RCFS compression")
	}
	offsets, err := im.offsets(n)
	if err != nil {
		return 0, err
	}
	return offsets[len(offsets)-1], nil
}
func (im *Image) Data(n Node, w io.Writer) error {
	if n.Mode&0xf000 != 0x8000 && n.Mode&0xf000 != 0xa000 {
		return fmt.Errorf("RCFS inode has no file data")
	}
	if n.Size == 0 {
		return nil
	}
	if n.Extended>>7 == 0 {
		if err := im.R.Range(int64(n.Offset), int64(n.Size)); err != nil {
			return err
		}
		_, err := io.CopyN(w, io.NewSectionReader(im.R.ReaderAt, int64(n.Offset), int64(n.Size)), int64(n.Size))
		return err
	}
	if n.Extended>>7 != 1 {
		return fmt.Errorf("unsupported RCFS compression")
	}
	offsets, err := im.offsets(n)
	if err != nil {
		return err
	}
	left := int64(n.Size)
	for i := 0; i < len(offsets)-1; i++ {
		b, err := im.R.Bytes(int64(n.Offset)+int64(offsets[i]), int64(offsets[i+1]-offsets[i]))
		if err != nil {
			return err
		}
		size := min(int64(chunkSize), left)
		data, consumed, err := lzo.DecompressNInto(b, make([]byte, size))
		if err != nil {
			return fmt.Errorf("RCFS inode %d chunk %d: %w", n.Index, i, err)
		}
		if consumed != len(b) || int64(len(data)) != size {
			return fmt.Errorf("LZO chunk length mismatch")
		}
		if _, err = w.Write(data); err != nil {
			return err
		}
		left -= size
	}
	return nil
}

type Report struct {
	Inodes, Files, Links, VerifiedHashes int
	ExternalSignature                    string
}

func (im *Image) Verify() (Report, error) {
	return im.verify(nil)
}
func (im *Image) verify(corrupted map[uint32]bool) (Report, error) {
	report := Report{ExternalSignature: "not authenticated"}
	seen := map[uint32]bool{}
	var walk func(Node, int) error
	walk = func(n Node, depth int) error {
		if depth > 1024 || seen[n.Index] {
			return fmt.Errorf("cyclic/shared RCFS inode tree")
		}
		seen[n.Index] = true
		report.Inodes++
		switch n.Mode & 0xf000 {
		case 0x4000:
			children, err := im.Children(n)
			if err != nil {
				return err
			}
			for _, c := range children {
				if err = walk(c, depth+1); err != nil {
					return err
				}
			}
		case 0x8000, 0xa000:
			if n.Mode&0xf000 == 0x8000 {
				report.Files++
			} else {
				report.Links++
			}
			if n.Index == im.Verifier.Index {
				return nil
			}
			v, ok := im.Hashes[n.Index]
			if !ok {
				return fmt.Errorf("RCFS inode %d missing VSIG hash", n.Index)
			}
			if corrupted[n.Index] {
				report.VerifiedHashes++
				return nil
			}
			size, err := im.PackedSize(n)
			if err != nil {
				return err
			}
			if size != v.PackedSize {
				return fmt.Errorf("RCFS inode %d packed size mismatch", n.Index)
			}
			h := sha256.New()
			if _, err = io.CopyN(h, io.NewSectionReader(im.R.ReaderAt, int64(n.Offset), int64(size)), int64(size)); err != nil {
				return err
			}
			if !bytes.Equal(h.Sum(nil), v.Hash[:]) {
				return fmt.Errorf("RCFS inode %d packed SHA256 mismatch", n.Index)
			}
			if err = im.Data(n, io.Discard); err != nil {
				return err
			}
			report.VerifiedHashes++
		default:
			return fmt.Errorf("unsupported RCFS inode type")
		}
		return nil
	}
	root, err := im.Node(1)
	if err != nil {
		return report, err
	}
	err = walk(root, 0)
	if err != nil {
		return report, err
	}
	if len(seen) != int(im.Count) {
		return report, fmt.Errorf("unreachable RCFS inodes")
	}
	if report.VerifiedHashes != len(im.Hashes) {
		return report, fmt.Errorf("unreferenced VSIG hashes")
	}
	return report, nil
}
