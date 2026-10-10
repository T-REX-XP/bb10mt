package qnx6

// reservedBlocks includes both metadata regions. Bitmap zero bits inside the
// inactive region are unavailable to ordinary files and do not count as free.
func reservedBlocks(inodes, blocks, bs uint32) uint64 {
	ceil := func(n, d uint64) uint64 { return (n + d - 1) / d }
	extra := func(n uint64) uint64 {
		var result uint64
		for n > 16 {
			n = ceil(n, uint64(bs/4))
			result += n
		}
		return result
	}
	it := ceil(uint64(inodes)*128, uint64(bs))
	bm := ceil(ceil(uint64(blocks), 8), uint64(bs))
	return 2 * (it + extra(it) + bm + extra(bm))
}
func freeBlocks(bitmap []byte, blocks uint32, reserved uint64) uint32 {
	var count uint32
	for n := reserved; n < uint64(blocks); n++ {
		if bitmap[n/8]&(1<<(n%8)) == 0 {
			count++
		}
	}
	return count
}
