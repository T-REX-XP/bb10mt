// Package qnx6 implements the on-disk BB10 QNX6 filesystem formats.
package qnx6

// LongNameChecksum is the BB10 kernel recurrence. The conditional XOR happens
// after the addition; rotate-and-add is a different operation on carry.
func LongNameChecksum(name []byte) uint32 {
	var v uint32
	for _, b := range name {
		low := v & 1
		v = (v >> 1) + uint32(b)
		if low != 0 {
			v ^= 0x80000000
		}
	}
	return v
}

// CRC is QNX's non-reflected CRC32, init=0, xorout=0 (not IEEE CRC32).
func CRC(data []byte) uint32 {
	var v uint32
	for _, b := range data {
		v ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if v&0x80000000 != 0 {
				v = (v << 1) ^ 0x04c11db7
			} else {
				v <<= 1
			}
		}
	}
	return v
}
