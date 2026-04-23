package shreddy

import "errors"

var errMalformedTx = errors.New("malformed transaction")

type txParser struct {
	data []byte
	off  int
}

func (p *txParser) remaining() int {
	return len(p.data) - p.off
}

// compactU16 parses a compact-u16 from the current offset. Returns ok=false
// if the encoding runs past the end of data.
func (p *txParser) compactU16() (v uint16, ok bool) {
	if p.off >= len(p.data) {
		return 0, false
	}
	b := p.data[p.off]
	if b < 0x80 {
		p.off++
		return uint16(b), true
	}
	if p.off+1 >= len(p.data) {
		return 0, false
	}
	val := uint16(b & 0x7f)
	b = p.data[p.off+1]
	if b < 0x80 {
		p.off += 2
		return val | uint16(b)<<7, true
	}
	if p.off+2 >= len(p.data) {
		return 0, false
	}
	c := p.data[p.off+2]
	p.off += 3
	return val | uint16(b&0x7f)<<7 | uint16(c&0x03)<<14, true
}

func transactionLength(data []byte) (int, error) {
	p := txParser{data: data}

	numSigs, ok := p.compactU16()
	if !ok || numSigs == 0 || p.remaining() < int(numSigs)*64 {
		return 0, errMalformedTx
	}
	p.off += int(numSigs) * 64

	if p.remaining() < 1 {
		return 0, errMalformedTx
	}
	versioned := p.data[p.off] >= 0x80
	if versioned {
		p.off++
	}

	if p.remaining() < 3 {
		return 0, errMalformedTx
	}
	p.off += 3

	numKeys, ok := p.compactU16()
	if !ok || p.remaining() < int(numKeys)*32 {
		return 0, errMalformedTx
	}
	p.off += int(numKeys) * 32

	if p.remaining() < 32 {
		return 0, errMalformedTx
	}
	p.off += 32

	numIx, ok := p.compactU16()
	if !ok {
		return 0, errMalformedTx
	}
	for i := uint16(0); i < numIx; i++ {
		if p.remaining() < 1 {
			return 0, errMalformedTx
		}
		p.off++

		numAccs, ok := p.compactU16()
		if !ok || p.remaining() < int(numAccs) {
			return 0, errMalformedTx
		}
		p.off += int(numAccs)

		dataLen, ok := p.compactU16()
		if !ok || p.remaining() < int(dataLen) {
			return 0, errMalformedTx
		}
		p.off += int(dataLen)
	}

	if versioned {
		numLookups, ok := p.compactU16()
		if !ok {
			return 0, errMalformedTx
		}
		for i := uint16(0); i < numLookups; i++ {
			if p.remaining() < 32 {
				return 0, errMalformedTx
			}
			p.off += 32

			numWritable, ok := p.compactU16()
			if !ok || p.remaining() < int(numWritable) {
				return 0, errMalformedTx
			}
			p.off += int(numWritable)

			numReadonly, ok := p.compactU16()
			if !ok || p.remaining() < int(numReadonly) {
				return 0, errMalformedTx
			}
			p.off += int(numReadonly)
		}
	}

	return p.off, nil
}
