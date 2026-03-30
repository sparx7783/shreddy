package shreddy

import (
	"encoding/binary"
	"errors"
)

var (
	errEntryTooShort = errors.New("entry: short read")
	errEntryTxLen    = errors.New("entry: bad transaction length")
)

func (en *Entry) unmarshal(data []byte, off int) (int, error) {
	if len(data)-off < 48 {
		return off, errEntryTooShort
	}

	en.NumHashes = binary.LittleEndian.Uint64(data[off:])
	off += 8

	copy(en.Hash[:], data[off:off+32])
	off += 32

	txCount := binary.LittleEndian.Uint64(data[off:])
	off += 8

	if txCount == 0 {
		return off, nil
	}

	txStart := off
	lengths := make([]int, txCount)
	totalTxBytes := 0
	for i := uint64(0); i < txCount; i++ {
		txLen, err := transactionLength(data[off:])
		if err != nil {
			return off, errEntryTxLen
		}
		if off+txLen > len(data) {
			return off, errEntryTooShort
		}
		lengths[i] = txLen
		totalTxBytes += txLen
		off += txLen
	}

	backing := make([]byte, totalTxBytes)
	copy(backing, data[txStart:txStart+totalTxBytes])

	en.TxBytes = make([][]byte, txCount)
	pos := 0
	for i := uint64(0); i < txCount; i++ {
		en.TxBytes[i] = backing[pos : pos+lengths[i]]
		pos += lengths[i]
	}
	return off, nil
}
