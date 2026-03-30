package shreddy

import "math/bits"

type bitset [MaxDataShredsPerSlot / 64]uint64

func (b *bitset) set(i uint32)      { b[i/64] |= uint64(1) << (i % 64) }
func (b *bitset) clear(i uint32)    { b[i/64] &^= uint64(1) << (i % 64) }
func (b *bitset) has(i uint32) bool { return b[i/64]&(uint64(1)<<(i%64)) != 0 }

func (b *bitset) prevSet(i uint32) (uint32, bool) {
	if i == 0 {
		return 0, false
	}
	i--
	w := i / 64
	bit := i % 64
	masked := b[w] & (^uint64(0) >> (63 - bit))
	if masked != 0 {
		return w*64 + uint32(63-bits.LeadingZeros64(masked)), true
	}
	for w > 0 {
		w--
		if b[w] != 0 {
			return w*64 + uint32(63-bits.LeadingZeros64(b[w])), true
		}
	}
	return 0, false
}

func (b *bitset) nextSet(i uint32) (uint32, bool) {
	w := i / 64
	if w >= uint32(len(b)) {
		return 0, false
	}
	bit := i % 64
	masked := b[w] >> bit
	if masked != 0 {
		return i + uint32(bits.TrailingZeros64(masked)), true
	}
	for w++; w < uint32(len(b)); w++ {
		if b[w] != 0 {
			return w*64 + uint32(bits.TrailingZeros64(b[w])), true
		}
	}
	return 0, false
}
