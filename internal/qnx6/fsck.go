package qnx6

import (
	"fmt"
	"math/bits"
	"sort"

	"github.com/bb10root/bb10mt/internal/binio"
)

type CheckReport struct {
	Audit              Audit    `json:"nameAudit"`
	ReferencedBlocks   int      `json:"referencedBlocks"`
	Errors             []string `json:"errors"`
	UsedBlocks         uint32   `json:"usedBlocks"`
	UsedInodes         uint32   `json:"usedInodes"`
	ExpectedFreeBlocks uint32   `json:"expectedFreeBlocks"`
}

// references returns data and indirect blocks for a complete node extent.
func (im *Image) references(raw []byte, ptr, level int, sparse bool) ([]uint32, error) {
	size := binio.U64(raw, 0)
	count := size / uint64(im.BlockSize)
	if size%uint64(im.BlockSize) != 0 {
		count++
	}
	depth := int(raw[level])
	if depth > 3 || count > uint64(im.Blocks) {
		return nil, fmt.Errorf("invalid inode extent")
	}
	var refs []uint32
	var seen uint64
	active := map[uint32]bool{}
	var walk func(uint32, int) error
	walk = func(n uint32, d int) error {
		if seen >= count {
			return nil
		}
		capacity := uint64(1)
		for j := 0; j < d; j++ {
			capacity *= uint64(im.BlockSize / 4)
		}
		if n == Missing {
			if !sparse {
				return fmt.Errorf("missing metadata block")
			}
			seen += min(count-seen, capacity)
			return nil
		}
		off, e := im.block(n)
		if e != nil {
			return e
		}
		refs = append(refs, n)
		if d == 0 {
			seen++
			return nil
		}
		if active[n] {
			return fmt.Errorf("cyclic block chain")
		}
		active[n] = true
		defer delete(active, n)
		b, e := im.cached(off)
		if e != nil {
			return e
		}
		for p := 0; p < len(b) && seen < count; p += 4 {
			if e = walk(binio.U32(b, p), d-1); e != nil {
				return e
			}
		}
		return nil
	}
	for i := 0; i < 16 && seen < count; i++ {
		if e := walk(binio.U32(raw, ptr+i*4), depth); e != nil {
			return nil, e
		}
	}
	if seen != count {
		return nil, fmt.Errorf("incomplete inode chain")
	}
	return refs, nil
}
func (im *Image) bitmap() ([]byte, []int64, error) {
	raw := im.Super[152:232]
	blocks, size, e := im.positions(raw, 8, 72, false)
	if e != nil {
		return nil, nil, e
	}
	needed := (uint64(im.Blocks) + 7) / 8
	if size < needed || needed > 64<<20 {
		return nil, nil, fmt.Errorf("invalid bitmap size")
	}
	b, e := im.tableRead(blocks, size, 0, int(needed))
	return b, blocks, e
}

func (im *Image) Check() (CheckReport, error) {
	report := CheckReport{Errors: []string{}}
	a, e := im.AuditNames()
	if e != nil {
		return report, e
	}
	report.Audit = a
	for _, v := range a.Issues {
		report.Errors = append(report.Errors, fmt.Sprintf("bad long-name checksum in directory %d: %s", v.Directory, v.Name))
	}
	bitmap, _, e := im.bitmap()
	if e != nil {
		return report, e
	}
	claimed := map[uint32]string{}
	links := map[uint32]uint32{}
	allocated := map[uint32]uint16{}
	directoryChildren := map[uint32][]uint32{}
	dotParents := map[uint32]uint32{}
	claim := func(refs []uint32, owner string) {
		for _, n := range refs {
			if prev, ok := claimed[n]; ok {
				report.Errors = append(report.Errors, fmt.Sprintf("block %d shared by %s and %s", n, prev, owner))
			} else {
				claimed[n] = owner
			}
			if bitmap[n/8]&(1<<(n%8)) == 0 {
				report.Errors = append(report.Errors, fmt.Sprintf("referenced block %d marked free", n))
			}
		}
	}
	for _, v := range []struct {
		off  int
		name string
	}{{72, "inode table"}, {152, "bitmap"}, {232, "long-name table"}, {312, "iclaim"}, {392, "iextra"}} {
		refs, e := im.references(im.Super[v.off:v.off+80], 8, 72, false)
		if e != nil {
			return report, fmt.Errorf("%s: %w", v.name, e)
		}
		claim(refs, v.name)
	}
	for i := uint32(1); i <= im.Inodes; i++ {
		n, e := im.Inode(i)
		if e != nil {
			return report, e
		}
		if n.Mode() == 0 {
			continue
		}
		// BB10's stock images and the original writer mark allocated inodes
		// active at byte 101. A mode alone must not make a zero-status inode
		// appear valid to the offline checker.
		if n.Raw[101] == 0 {
			report.Errors = append(report.Errors, fmt.Sprintf("allocated inode %d has zero status", i))
		}
		if n.Mode()&0xf000 == 0x4000 && n.Size()%uint64(im.BlockSize) != 0 {
			report.Errors = append(report.Errors, fmt.Sprintf("directory %d size %d is not block aligned", i, n.Size()))
		}
		allocated[i] = n.Links()
		refs, e := im.references(n.Raw, 36, 100, n.Mode()&0xf000 != 0x4000)
		if e != nil {
			return report, fmt.Errorf("inode %d: %w", i, e)
		}
		claim(refs, fmt.Sprintf("inode %d", i))
		if n.Mode()&0xf000 == 0x4000 {
			entries, e := im.Entries(n)
			if e != nil {
				return report, e
			}
			dot, dotdot := false, false
			for _, v := range entries {
				links[v.Inode]++
				if v.Name != "." && v.Name != ".." {
					directoryChildren[i] = append(directoryChildren[i], v.Inode)
				}
				if v.Name == "." {
					dot = v.Inode == i
				}
				if v.Name == ".." {
					dotParents[i] = v.Inode
					parent, e := im.Inode(v.Inode)
					dotdot = e == nil && parent.Mode()&0xf000 == 0x4000
				}
			}
			if !dot || !dotdot {
				report.Errors = append(report.Errors, fmt.Sprintf("invalid dot entries in directory %d", i))
			}
		}
	}
	for n, want := range allocated {
		if links[n] != uint32(want) {
			report.Errors = append(report.Errors, fmt.Sprintf("inode %d link count %d, directory references %d", n, want, links[n]))
		}
	}
	for n := range links {
		if _, ok := allocated[n]; !ok {
			report.Errors = append(report.Errors, fmt.Sprintf("directory references free inode %d", n))
		}
	}
	root, err := im.Inode(1)
	if err != nil {
		return report, err
	}
	if root.Mode()&0xf000 != 0x4000 {
		report.Errors = append(report.Errors, "root inode is not a directory")
	}
	parents := map[uint32]uint32{1: 1}
	for parent, children := range directoryChildren {
		for _, child := range children {
			if _, isDir := dotParents[child]; !isDir {
				continue
			}
			if _, exists := parents[child]; exists {
				report.Errors = append(report.Errors, fmt.Sprintf("directory %d has multiple parent links or a cycle", child))
			} else {
				parents[child] = parent
			}
		}
	}
	for child, actual := range dotParents {
		if expected, ok := parents[child]; ok && expected != actual {
			report.Errors = append(report.Errors, fmt.Sprintf("directory %d has wrong parent entry", child))
		}
	}
	reachable := map[uint32]bool{}
	queue := []uint32{1}
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if reachable[n] {
			continue
		}
		reachable[n] = true
		queue = append(queue, directoryChildren[n]...)
	}
	for n := range allocated {
		if !reachable[n] {
			report.Errors = append(report.Errors, fmt.Sprintf("inode %d is unreachable from root", n))
		}
	}
	if uint64(len(allocated))+uint64(binio.U32(im.Super, 56)) != uint64(im.Inodes) {
		report.Errors = append(report.Errors, "free inode count mismatch")
	}
	var used uint64
	for i, b := range bitmap {
		if i == len(bitmap)-1 && im.Blocks%8 != 0 {
			b &= byte((1 << (im.Blocks % 8)) - 1)
		}
		used += uint64(bits.OnesCount8(b))
	}
	reserved := reservedBlocks(im.Inodes, im.Blocks, im.BlockSize)
	if reserved >= uint64(im.Blocks) {
		return report, fmt.Errorf("invalid reserved metadata area")
	}
	for n := uint32(reserved); n < im.Blocks; n++ {
		if bitmap[n/8]&(1<<(n%8)) != 0 {
			if _, ok := claimed[n]; !ok {
				report.Errors = append(report.Errors, fmt.Sprintf("allocated block %d is unreferenced", n))
			}
		}
	}
	report.ExpectedFreeBlocks = freeBlocks(bitmap, im.Blocks, reserved)
	if report.ExpectedFreeBlocks != binio.U32(im.Super, 64) {
		report.Errors = append(report.Errors, "free block count mismatch")
	}
	report.UsedBlocks = uint32(used)
	report.UsedInodes = uint32(len(allocated))
	report.ReferencedBlocks = len(claimed)
	sort.Strings(report.Errors)
	return report, nil
}
