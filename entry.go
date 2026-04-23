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
		en.TxBytes = nil
		return off, nil
	}

	// Pass 1: decode every tx length once. Cache in a stack-local buffer
	// for the typical case so pass 2 does not re-parse.
	var stackLens [64]int
	var lens []int
	if txCount <= uint64(len(stackLens)) {
		lens = stackLens[:txCount]
	} else {
		lens = make([]int, txCount)
	}

	totalTxBytes := 0
	scanOff := off
	for i := uint64(0); i < txCount; i++ {
		txLen, err := transactionLength(data[scanOff:])
		if err != nil {
			return off, errEntryTxLen
		}
		if scanOff+txLen > len(data) {
			return off, errEntryTooShort
		}
		lens[i] = txLen
		totalTxBytes += txLen
		scanOff += txLen
	}

	// Pass 2: copy once, slice into backing using cached lengths.
	backing := make([]byte, totalTxBytes)
	copy(backing, data[off:off+totalTxBytes])
	en.TxBytes = make([][]byte, txCount)
	pos := 0
	for i := uint64(0); i < txCount; i++ {
		n := lens[i]
		en.TxBytes[i] = backing[pos : pos+n]
		pos += n
	}
	return off + totalTxBytes, nil
}
