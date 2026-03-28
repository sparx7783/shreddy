package shreddy

import (
	"sync"

	"github.com/gagliardetto/solana-go"
	"github.com/klauspost/reedsolomon"
)

// Shred types taken from https://github.com/firedancer-io/radiance
type Shred struct {
	CommonHeader
	DataHeader
	CodeHeader
	Payload      []byte
	RawPayload   []byte
	ErasureShard []byte
}

type Entry struct {
	Slot      uint64
	NumHashes uint64
	Hash      solana.Hash
	TxBytes   [][]byte
}
type CommonHeader struct {
	Signature   solana.Signature
	Variant     uint8
	Slot        uint64
	Index       uint32
	Version     uint16
	FECSetIndex uint32
}

type DataHeader struct {
	ParentOffset uint16
	Flags        uint8
	Size         uint16
}

type CodeHeader struct {
	NumDataShreds uint16
	NumCodeShreds uint16
	Position      uint16
}

const (
	MerkleTypeMask  = uint8(0b11000000)
	MerkleDepthMask = uint8(0x0F)

	MerkleCodeID = uint8(0x40)
	MerkleDataID = uint8(0x80)
)

const (
	FlagDataTickMask   = uint8(0b0011_1111)
	FlagDataEndOfBatch = uint8(0b0100_0000)
	FlagDataEndOfBlock = uint8(0b1100_0000)
)

const (
	DataHeaderSize           = 88
	MerkleCodeHeaderSize     = 89
	MerkleDataPayloadSize    = 1203
	MerkleCodePayloadSize    = 1228
	MerkleRootSize           = 32
	MerkleProofEntrySize     = 20
	PacketDataSize           = 1232
	NonceSize                = 4
	DataShredsPerFECBlock    = 32
	MaxCodeShredsPerFECBlock = 256
)

type FECSetState struct {
	slot        uint64
	fecSetIndex uint32
	numData     int
	numCode     int
	shardSize   int
	dataCount   int
	codeCount   int
	recovered   bool
	data        [DataShredsPerFECBlock]*Shred
	code        [MaxCodeShredsPerFECBlock]*Shred
}

type rsKey struct {
	data      int
	parity    int
	shardSize int
}

type rsCache struct {
	mu   sync.RWMutex
	encs map[rsKey]reedsolomon.Encoder
}
