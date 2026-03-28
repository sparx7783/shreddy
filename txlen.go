package shred

import "errors"

var errMalformedTx = errors.New("malformed transaction")

type txParser struct {
	data []byte
	off  int
}

func (p *txParser) remaining() int {
	return len(p.data) - p.off
}

func (p *txParser) compactU16() uint16 {
	b := p.data[p.off]
	if b < 0x80 {
		p.off++
		return uint16(b)
	}
	val := uint16(b & 0x7f)
	b = p.data[p.off+1]
	if b < 0x80 {
		p.off += 2
		return val | uint16(b)<<7
	}
	p.off += 3
	return val | uint16(b&0x7f)<<7 | uint16(p.data[p.off-1]&0x03)<<14
}

func transactionLength(data []byte) (length int, err error) {
	defer func() {
		if r := recover(); r != nil {
			length, err = 0, errMalformedTx
		}
	}()

	p := txParser{data: data}

	numSigs := int(p.compactU16())
	if numSigs <= 0 || p.remaining() < numSigs*64 {
		return 0, errMalformedTx
	}
	p.off += numSigs * 64

	if p.remaining() < 1 {
		return 0, errMalformedTx
	}
	versioned := data[p.off] >= 0x80
	if versioned {
		p.off++
	}

	if p.remaining() < 3 {
		return 0, errMalformedTx
	}
	p.off += 3

	numKeys := int(p.compactU16())
	if numKeys < 0 || p.remaining() < numKeys*32 {
		return 0, errMalformedTx
	}
	p.off += numKeys * 32

	if p.remaining() < 32 {
		return 0, errMalformedTx
	}
	p.off += 32

	numIx := int(p.compactU16())
	for i := 0; i < numIx; i++ {
		if p.remaining() < 1 {
			return 0, errMalformedTx
		}
		p.off++

		numAccs := int(p.compactU16())
		if numAccs < 0 || p.remaining() < numAccs {
			return 0, errMalformedTx
		}
		p.off += numAccs

		dataLen := int(p.compactU16())
		if dataLen < 0 || p.remaining() < dataLen {
			return 0, errMalformedTx
		}
		p.off += dataLen
	}

	if versioned {
		numLookups := int(p.compactU16())
		for i := 0; i < numLookups; i++ {
			if p.remaining() < 32 {
				return 0, errMalformedTx
			}
			p.off += 32

			numWritable := int(p.compactU16())
			if numWritable < 0 || p.remaining() < numWritable {
				return 0, errMalformedTx
			}
			p.off += numWritable

			numReadonly := int(p.compactU16())
			if numReadonly < 0 || p.remaining() < numReadonly {
				return 0, errMalformedTx
			}
			p.off += numReadonly
		}
	}

	return p.off, nil
}
