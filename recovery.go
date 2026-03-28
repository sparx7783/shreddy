package shred

import (
	"encoding/binary"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

func (c *rsCache) get(data, parity, shardSize int) (reedsolomon.Encoder, error) {
	key := rsKey{
		data:      data,
		parity:    parity,
		shardSize: shardSize,
	}

	c.mu.RLock()
	if enc := c.encs[key]; enc != nil {
		c.mu.RUnlock()
		return enc, nil
	}
	c.mu.RUnlock()

	enc, err := reedsolomon.New(data, parity, reedsolomon.WithAutoGoroutines(shardSize))
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encs == nil {
		c.encs = make(map[rsKey]reedsolomon.Encoder)
	}
	if existing := c.encs[key]; existing != nil {
		return existing, nil
	}
	c.encs[key] = enc
	return enc, nil
}

func (a *Assembler) tryRecoverFEC(set *FECSetState) ([]*Shred, error) {
	if set == nil || set.numData == 0 || set.numCode == 0 || set.shardSize == 0 {
		return nil, nil
	}
	if set.dataCount == set.numData {
		return nil, nil
	}
	if set.dataCount+set.codeCount < set.numData {
		return nil, nil
	}

	enc, err := a.rs.get(set.numData, set.numCode, set.shardSize)
	if err != nil {
		return nil, err
	}

	shards := make([][]byte, set.numData+set.numCode)
	for i := 0; i < set.numData; i++ {
		if sh := set.data[i]; sh != nil {
			shards[i] = append([]byte(nil), sh.ErasureShard...)
		}
	}
	for i := 0; i < set.numCode; i++ {
		if sh := set.code[i]; sh != nil {
			shards[set.numData+i] = append([]byte(nil), sh.ErasureShard...)
		}
	}

	if err := enc.ReconstructData(shards); err != nil {
		return nil, err
	}

	var recovered []*Shred
	for i := 0; i < set.numData; i++ {
		if set.data[i] != nil || len(shards[i]) == 0 {
			continue
		}

		sh, err := recoveredDataShred(set, i, shards[i])
		if err != nil {
			return nil, err
		}
		set.data[i] = sh
		set.dataCount++
		recovered = append(recovered, sh)
	}

	set.recovered = true
	return recovered, nil
}

func recoveredDataShred(set *FECSetState, shardIndex int, shard []byte) (*Shred, error) {
	if len(shard) < 24 {
		return nil, fmt.Errorf("short reconstructed shard: %d", len(shard))
	}

	sh := &Shred{}
	sh.Variant = shard[0]
	sh.Slot = binary.LittleEndian.Uint64(shard[1:9])
	sh.Index = binary.LittleEndian.Uint32(shard[9:13])
	sh.Version = binary.LittleEndian.Uint16(shard[13:15])
	sh.FECSetIndex = binary.LittleEndian.Uint32(shard[15:19])
	sh.DataHeader.ParentOffset = binary.LittleEndian.Uint16(shard[19:21])
	sh.DataHeader.Flags = shard[21]
	sh.DataHeader.Size = binary.LittleEndian.Uint16(shard[22:24])
	sh.ErasureShard = append([]byte(nil), shard...)

	payloadLen := int(sh.DataHeader.Size) - DataHeaderSize
	if payloadLen < 0 || payloadLen > len(shard)-24 {
		return nil, fmt.Errorf("invalid reconstructed payload size: %d", payloadLen)
	}

	sh.Payload = append([]byte(nil), shard[24:24+payloadLen]...)
	if !sh.Sanitize() {
		return nil, fmt.Errorf("recovered shred failed sanitize: index=%d", sh.Index)
	}

	expectedIndex := set.fecSetIndex + uint32(shardIndex)
	if sh.Index != expectedIndex {
		return nil, fmt.Errorf("recovered wrong shred index: got %d want %d", sh.Index, expectedIndex)
	}

	return sh, nil
}
