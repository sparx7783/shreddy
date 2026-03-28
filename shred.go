package shred

import (
	"encoding/binary"
)

// some code taken from https://github.com/firedancer-io/radiance

func merkleResigned(variant uint8) bool {
	return variant&0x10 != 0
}

func merkleCapacity(totalSize, headerSize, proofSize int, resigned bool) (int, bool) {
	n := totalSize - headerSize - MerkleRootSize - proofSize*MerkleProofEntrySize
	if resigned {
		n -= 64
	}
	return n, n >= 0
}

func erasureShardBounds(variant uint8) (start, end, total int, ok bool) {
	proofSize := int(variant & MerkleDepthMask)
	resigned := merkleResigned(variant)

	switch {
	case (variant & MerkleTypeMask) == MerkleDataID:
		capacity, good := merkleCapacity(MerkleDataPayloadSize, DataHeaderSize, proofSize, resigned)
		if !good {
			return 0, 0, 0, false
		}
		return 64, DataHeaderSize + capacity, MerkleDataPayloadSize, true
	case (variant & MerkleTypeMask) == MerkleCodeID:
		capacity, good := merkleCapacity(MerkleCodePayloadSize, MerkleCodeHeaderSize, proofSize, resigned)
		if !good {
			return 0, 0, 0, false
		}
		return MerkleCodeHeaderSize, MerkleCodeHeaderSize + capacity, MerkleCodePayloadSize, true
	default:
		return 0, 0, 0, false
	}
}

func NewShredFromSerialized(shred []byte) (s Shred) {
	if len(shred) < DataHeaderSize {
		return
	}
	variant := shred[64]

	switch {
	case (variant & MerkleTypeMask) == MerkleCodeID:
		if len(shred) < MerkleCodeHeaderSize {
			return
		}
		s.CodeHeader.NumDataShreds = binary.LittleEndian.Uint16(shred[0x53:0x55])
		s.CodeHeader.NumCodeShreds = binary.LittleEndian.Uint16(shred[0x55:0x57])
		s.CodeHeader.Position = binary.LittleEndian.Uint16(shred[0x57:0x59])

		start, end, total, ok := erasureShardBounds(variant)
		if !ok || len(shred) < total || end > total {
			return
		}

		s.RawPayload = make([]byte, total)
		copy(s.RawPayload, shred[:total])
		s.ErasureShard = s.RawPayload[start:end]
	case (variant & MerkleTypeMask) == MerkleDataID:

		s.DataHeader.ParentOffset = binary.LittleEndian.Uint16(shred[0x53:0x55])
		s.DataHeader.Flags = shred[0x55]
		s.DataHeader.Size = binary.LittleEndian.Uint16(shred[0x56:0x58])
		payloadOff := DataHeaderSize
		merkleDepth := int(variant & MerkleDepthMask)
		merkleProofSize := merkleDepth * MerkleProofEntrySize
		payloadSize := int(s.DataHeader.Size) - DataHeaderSize
		if payloadSize < 0 {
			return
		}
		start, end, total, ok := erasureShardBounds(variant)
		if !ok || len(shred) < total || end > total {
			return
		}
		if len(shred) < int(s.DataHeader.Size)+merkleProofSize {
			return
		}
		payloadEnd := payloadOff + payloadSize
		if payloadEnd > total {
			return
		}

		s.RawPayload = make([]byte, total)
		copy(s.RawPayload, shred[:total])
		s.Payload = s.RawPayload[payloadOff:payloadEnd]
		s.ErasureShard = s.RawPayload[start:end]
	default:
		return
	}

	copy(s.Signature[:], shred[0x00:0x40])
	s.Variant = variant
	s.Slot = binary.LittleEndian.Uint64(shred[0x41:0x49])
	s.Index = binary.LittleEndian.Uint32(shred[0x49:0x4d])
	s.Version = binary.LittleEndian.Uint16(shred[0x4d:0x4f])
	s.FECSetIndex = binary.LittleEndian.Uint32(shred[0x4f:0x53])
	return
}

func (c *CommonHeader) Ok() bool {
	return c.IsData() || c.IsCode()
}

func (c *CommonHeader) IsData() bool {
	return (c.Variant & MerkleTypeMask) == MerkleDataID
}

func (c *CommonHeader) IsCode() bool {
	return (c.Variant & MerkleTypeMask) == MerkleCodeID
}

func (d *DataHeader) EndOfBlock() bool {
	return d.Flags&FlagDataEndOfBlock == FlagDataEndOfBlock
}

func (s *DataHeader) EndOfBatch() bool {
	return s.Flags&FlagDataEndOfBatch != 0
}

func (s *DataHeader) Tick() uint8 {
	return s.Flags & FlagDataTickMask
}

func (s *Shred) Sanitize() bool {
	if s.IsCode() {
		return s.Index < MaxDataShredsPerSlot &&
			s.CodeHeader.NumDataShreds > 0 && s.CodeHeader.NumDataShreds <= DataShredsPerFECBlock &&
			s.CodeHeader.NumCodeShreds > 0 && s.CodeHeader.NumCodeShreds <= MaxCodeShredsPerFECBlock &&
			s.CodeHeader.Position < s.CodeHeader.NumCodeShreds &&
			len(s.ErasureShard) > 0
	}
	if !s.IsData() {
		return false
	}
	return s.Index < MaxDataShredsPerSlot &&
		s.FECSetIndex < MaxDataShredsPerSlot &&
		s.Index >= s.FECSetIndex &&
		(s.Slot == 0 || s.DataHeader.ParentOffset > 0) &&
		uint64(s.DataHeader.ParentOffset) <= s.Slot &&
		(s.DataHeader.Flags&FlagDataEndOfBlock == 0 || s.DataHeader.Flags&FlagDataEndOfBatch != 0) &&
		len(s.ErasureShard) > 0
}
