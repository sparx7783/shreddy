package shreddy

import (
	"encoding/binary"
	"testing"

	"github.com/klauspost/reedsolomon"
)

// --- fixtures ---------------------------------------------------------------

const (
	testProofDepth    = 6
	testProofSize     = testProofDepth * MerkleProofEntrySize
	testDataVariant   = MerkleDataID | uint8(testProofDepth)
	testCodeVariant   = MerkleCodeID | uint8(testProofDepth)
	testDataShardSize = MerkleDataPayloadSize - DataHeaderSize - MerkleRootSize - testProofSize + (DataHeaderSize - 64)
	testCodeShardSize = MerkleCodePayloadSize - MerkleCodeHeaderSize - MerkleRootSize - testProofSize
)

// encodeCompactU16 appends the compact-u16 encoding of v to dst.
func encodeCompactU16(dst []byte, v uint16) []byte {
	if v < 0x80 {
		return append(dst, byte(v))
	}
	if v < 0x4000 {
		return append(dst, byte(v)|0x80, byte(v>>7))
	}
	return append(dst, byte(v)|0x80, byte(v>>7)|0x80, byte(v>>14))
}

// buildLegacyTx constructs a minimal, well-formed legacy transaction
// that transactionLength can parse.
func buildLegacyTx() []byte {
	tx := []byte{0x01}            // numSigs = 1
	tx = append(tx, make([]byte, 64)...) // signature
	tx = append(tx, 0x01, 0x00, 0x00)    // msg header (legacy, first byte < 0x80)
	tx = append(tx, 0x01)                // numKeys = 1
	tx = append(tx, make([]byte, 32)...) // key
	tx = append(tx, make([]byte, 32)...) // recent blockhash
	tx = append(tx, 0x00)                // numIx = 0
	return tx
}

// buildEntryPayload builds the concatenated payload bytes that assembled
// data shreds would contain: uint64 numEntries, followed by entries.
// Each entry: uint64 numHashes, 32 hash bytes, uint64 txCount, then txs.
func buildEntryPayload(numEntries, txsPerEntry int) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(numEntries))
	for i := 0; i < numEntries; i++ {
		hdr := make([]byte, 8+32+8)
		binary.LittleEndian.PutUint64(hdr[0:8], 10000)
		binary.LittleEndian.PutUint64(hdr[40:48], uint64(txsPerEntry))
		buf = append(buf, hdr...)
		for j := 0; j < txsPerEntry; j++ {
			buf = append(buf, buildLegacyTx()...)
		}
	}
	return buf
}

// buildDataShred constructs a MerkleDataPayloadSize-byte data shred with the
// given slot/index/fec layout and payload (written after the data header).
func buildDataShred(slot uint64, index, fecSetIndex uint32, flags uint8, payload []byte) []byte {
	buf := make([]byte, MerkleDataPayloadSize)
	buf[0x40] = testDataVariant
	binary.LittleEndian.PutUint64(buf[0x41:0x49], slot)
	binary.LittleEndian.PutUint32(buf[0x49:0x4d], index)
	binary.LittleEndian.PutUint16(buf[0x4d:0x4f], 1) // version
	binary.LittleEndian.PutUint32(buf[0x4f:0x53], fecSetIndex)
	binary.LittleEndian.PutUint16(buf[0x53:0x55], 1) // parent_offset
	buf[0x55] = flags
	binary.LittleEndian.PutUint16(buf[0x56:0x58], uint16(DataHeaderSize+len(payload)))
	copy(buf[DataHeaderSize:], payload)
	return buf
}

// buildCodeShredFromShard constructs a MerkleCodePayloadSize-byte code shred
// with the given header fields and an erasure shard laid out after the code header.
func buildCodeShredFromShard(slot uint64, index, fecSetIndex uint32, numData, numCode, pos uint16, shard []byte) []byte {
	buf := make([]byte, MerkleCodePayloadSize)
	buf[0x40] = testCodeVariant
	binary.LittleEndian.PutUint64(buf[0x41:0x49], slot)
	binary.LittleEndian.PutUint32(buf[0x49:0x4d], index)
	binary.LittleEndian.PutUint16(buf[0x4d:0x4f], 1)
	binary.LittleEndian.PutUint32(buf[0x4f:0x53], fecSetIndex)
	binary.LittleEndian.PutUint16(buf[0x53:0x55], numData)
	binary.LittleEndian.PutUint16(buf[0x55:0x57], numCode)
	binary.LittleEndian.PutUint16(buf[0x57:0x59], pos)
	copy(buf[MerkleCodeHeaderSize:], shard)
	return buf
}

// buildDataShredFromShard builds a data shred with the given erasure shard
// placed starting at byte 64 (so the shard begins with the data header).
func buildDataShredFromShard(slot uint64, shard []byte) []byte {
	buf := make([]byte, MerkleDataPayloadSize)
	copy(buf[64:], shard)
	return buf
}

// buildFECSet returns numData data shred bytes and numCode code shred bytes
// for a single FEC set at (slot, fecSetIndex). Each data shred carries a
// fragment of the entry payload so that, assembled, they parse back to one
// entry with txsPerEntry txs.
func buildFECSet(t testing.TB, slot uint64, fecSetIndex uint32, numData, numCode int, txsPerEntry int) (dataShreds, codeShreds [][]byte) {
	shardSize := testDataShardSize

	// Build one entry payload and split it across numData shreds.
	payload := buildEntryPayload(1, txsPerEntry)

	// Each data shred's "payload area" is from DataHeaderSize to
	// DataHeaderSize+capacity. capacity == shardSize - (DataHeaderSize - 64).
	perShredPayload := shardSize - (DataHeaderSize - 64)
	total := perShredPayload * numData
	if len(payload) > total {
		t.Fatalf("entry payload %d exceeds FEC capacity %d", len(payload), total)
	}
	padded := make([]byte, total)
	copy(padded, payload)

	shards := make([][]byte, numData+numCode)
	for i := 0; i < numData; i++ {
		shard := make([]byte, shardSize)
		// layout matches buildDataShred starting at byte 64:
		// shard[0]=variant, [1..9]=slot, [9..13]=index, [13..15]=version,
		// [15..19]=fecSetIndex, [19..21]=parentOffset, [21]=flags, [22..24]=size.
		shard[0] = testDataVariant
		binary.LittleEndian.PutUint64(shard[1:9], slot)
		binary.LittleEndian.PutUint32(shard[9:13], fecSetIndex+uint32(i))
		binary.LittleEndian.PutUint16(shard[13:15], 1)
		binary.LittleEndian.PutUint32(shard[15:19], fecSetIndex)
		binary.LittleEndian.PutUint16(shard[19:21], 1)
		flags := uint8(0)
		if i == numData-1 {
			flags = FlagDataEndOfBatch
		}
		shard[21] = flags
		// size covers DataHeaderSize + this shred's payload portion
		sz := uint16(DataHeaderSize + perShredPayload)
		binary.LittleEndian.PutUint16(shard[22:24], sz)
		// write this shred's slice of the overall payload after the header area
		copy(shard[(DataHeaderSize-64):], padded[i*perShredPayload:(i+1)*perShredPayload])
		shards[i] = shard
	}
	for i := 0; i < numCode; i++ {
		shards[numData+i] = make([]byte, shardSize)
	}

	enc, err := reedsolomon.New(numData, numCode)
	if err != nil {
		t.Fatalf("reedsolomon.New: %v", err)
	}
	if err := enc.Encode(shards); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	dataShreds = make([][]byte, numData)
	for i := 0; i < numData; i++ {
		dataShreds[i] = buildDataShredFromShard(slot, shards[i])
	}
	codeShreds = make([][]byte, numCode)
	for i := 0; i < numCode; i++ {
		codeShreds[i] = buildCodeShredFromShard(slot, fecSetIndex+uint32(numData+i), fecSetIndex,
			uint16(numData), uint16(numCode), uint16(i), shards[numData+i])
	}
	return dataShreds, codeShreds
}

// --- parse benchmarks -------------------------------------------------------

func BenchmarkParseDataShred(b *testing.B) {
	payload := buildEntryPayload(1, 2)
	raw := buildDataShred(100, 0, 0, FlagDataEndOfBatch, payload)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sh := NewShredFromSerialized(raw)
		if !sh.Ok() {
			b.Fatal("parse failed")
		}
		releaseShred(&sh)
	}
}

func BenchmarkParseCodeShred(b *testing.B) {
	_, code := buildFECSet(b, 100, 0, 4, 4, 1)
	raw := code[0]
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sh := NewShredFromSerialized(raw)
		if !sh.Ok() {
			b.Fatal("parse failed")
		}
		releaseShred(&sh)
	}
}

// --- entry / tx parsing -----------------------------------------------------

func BenchmarkTransactionLength(b *testing.B) {
	tx := buildLegacyTx()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := transactionLength(tx)
		if err != nil || n == 0 {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseEntries(b *testing.B) {
	// 4 entries, 8 txs each -> exercises per-entry allocation
	payload := buildEntryPayload(4, 8)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		entries, err := parseEntriesFromShredPayload(payload)
		if err != nil || len(entries) == 0 {
			b.Fatal(err)
		}
	}
}

// --- assembler --------------------------------------------------------------

// BenchmarkAssemblerPushData feeds all data shreds of one FEC set. One
// iteration processes numData shreds on a fresh slot, which exercises parse +
// tracker + concat + entry parse. The assembler is reused across iterations
// (its fixed arrays would otherwise dominate the measurement).
func BenchmarkAssemblerPushData(b *testing.B) {
	const numData = 8
	const numSlots = 1024
	sets := make([][][]byte, numSlots)
	for s := 0; s < numSlots; s++ {
		data, _ := buildFECSet(b, uint64(100+s), 0, numData, 0, 2)
		sets[s] = data
	}
	asm := NewAssembler()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data := sets[i%numSlots]
		for _, raw := range data {
			sh := NewShredFromSerialized(raw)
			asm.Push(&sh)
		}
	}
}

// --- FEC recovery -----------------------------------------------------------

// BenchmarkFECRecover drops half the data shreds, supplies enough code shreds
// to trigger recovery. The final Push call runs tryRecoverFEC.
func BenchmarkFECRecover(b *testing.B) {
	const numData = 8
	const numCode = 16
	const numSlots = 256
	type set struct{ data, code [][]byte }
	sets := make([]set, numSlots)
	for s := 0; s < numSlots; s++ {
		d, c := buildFECSet(b, uint64(100+s), 0, numData, numCode, 1)
		sets[s] = set{d, c}
	}
	asm := NewAssembler()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := sets[i%numSlots]
		for j := 0; j < numData/2; j++ {
			sh := NewShredFromSerialized(s.data[j])
			asm.Push(&sh)
		}
		for j := 0; j < numData-numData/2; j++ {
			sh := NewShredFromSerialized(s.code[j])
			asm.Push(&sh)
		}
	}
}
