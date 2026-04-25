package shreddy

import (
	"encoding/binary"
	"errors"
)

const (
	MaxDataShredsPerSlot = 32768
	MaxSlotsTracked      = 64
)

type Tracker struct {
	shredStatus    [MaxDataShredsPerSlot]uint8
	shredPointers  [MaxDataShredsPerSlot]*Shred
	indexProcessed [MaxDataShredsPerSlot]bool

	completedData bitset

	highestIndex uint32
	lowestIndex  uint32
	shredCount   uint32
}
type SlotState struct {
	tracker       *Tracker
	fecSets       [MaxDataShredsPerSlot]*FECSetState
	fecTouched    [MaxDataShredsPerSlot]uint32
	fecTouchedCnt uint32
}
type Assembler struct {
	slotStates [MaxSlotsTracked]*SlotState
	slotKeys   [MaxSlotsTracked]uint64
	slotCount  uint32

	segmentBuffer [MaxDataShredsPerSlot]*Shred
	payloadBuffer []byte
	rs            rsCache

	CurrentSlot uint64
	OnSlot      func(slot uint64)
}

func NewAssembler() *Assembler {
	a := &Assembler{
		payloadBuffer: make([]byte, 0, 4*1024*1024),
	}

	for i := range a.slotStates {
		a.slotStates[i] = &SlotState{
			tracker: &Tracker{
				lowestIndex:  ^uint32(0),
				highestIndex: 0,
			},
		}
	}

	return a
}

func (a *Assembler) Push(sh *Shred) [][]Entry {
	if !sh.Sanitize() {
		releaseShred(sh)
		return nil
	}

	slotState := a.getOrCreateSlotState(sh.Slot)
	set, stored, ok := a.addToFECSet(slotState, sh)
	if !ok {
		releaseShred(sh)
		return nil
	}

	if sh.IsCode() {
		if !stored {
			releaseShred(sh)
			return nil
		}
		if set.recovered {
			return nil
		}
		recovered, err := a.tryRecoverFEC(set)
		if err != nil || len(recovered) == 0 {
			return nil
		}
		return a.pushRecovered(slotState.tracker, recovered)
	}

	tracker := slotState.tracker
	if !stored || set.recovered || tracker.indexProcessed[sh.Index] {
		if !stored {
			releaseShred(sh)
		}
		return nil
	}

	if !a.updateTracker(sh, tracker) {
		// Reachable when a prior shred with the same global Index but a
		// different FECSetIndex already occupies the tracker slot.
		releaseShred(sh)
		return nil
	}

	batches := a.assemble(tracker, sh.Index)
	if len(batches) > 0 {
		return batches
	}
	return nil
}

func (a *Assembler) updateTracker(sh *Shred, tracker *Tracker) bool {
	index := sh.Index

	if tracker.shredStatus[index] != 0 {
		return false
	}

	if sh.DataHeader.EndOfBatch() || sh.DataHeader.EndOfBlock() {
		tracker.shredStatus[index] = 2
		tracker.completedData.set(index)
	} else {
		tracker.shredStatus[index] = 1
	}

	tracker.shredPointers[index] = sh

	if index < tracker.lowestIndex {
		tracker.lowestIndex = index
	}
	if index > tracker.highestIndex {
		tracker.highestIndex = index
	}

	tracker.shredCount++
	return true
}

func (a *Assembler) addToFECSet(slotState *SlotState, sh *Shred) (set *FECSetState, stored, ok bool) {
	fecSetIndex := sh.FECSetIndex
	set = slotState.fecSets[fecSetIndex]
	if set == nil {
		set = &FECSetState{
			slot:        sh.Slot,
			fecSetIndex: fecSetIndex,
		}
		slotState.fecSets[fecSetIndex] = set
		slotState.fecTouched[slotState.fecTouchedCnt] = fecSetIndex
		slotState.fecTouchedCnt++
	}

	if sh.IsData() {
		rel := int(sh.Index - sh.FECSetIndex)
		if rel < 0 || rel >= len(set.data) {
			return nil, false, false
		}
		if set.data[rel] == nil {
			set.data[rel] = sh
			set.dataCount++
			stored = true
		}
		if sh.ErasureShard != nil {
			set.shardSize = len(sh.ErasureShard)
		}
		if sh.DataHeader.EndOfBatch() || sh.DataHeader.EndOfBlock() {
			set.numData = rel + 1
		}
		return set, stored, true
	}

	if set.numData != 0 && set.numData != int(sh.CodeHeader.NumDataShreds) {
		return nil, false, false
	}
	if set.numCode != 0 && set.numCode != int(sh.CodeHeader.NumCodeShreds) {
		return nil, false, false
	}

	set.numData = int(sh.CodeHeader.NumDataShreds)
	set.numCode = int(sh.CodeHeader.NumCodeShreds)
	if sh.ErasureShard != nil {
		set.shardSize = len(sh.ErasureShard)
	}

	pos := int(sh.CodeHeader.Position)
	if set.code[pos] == nil {
		set.code[pos] = sh
		set.codeCount++
		stored = true
	}
	return set, stored, true
}

func (tracker *Tracker) findRange(idx uint32) (start, end uint32, found bool) {
	endIdx, ok := tracker.completedData.nextSet(idx)
	if !ok {
		return 0, 0, false
	}

	if prevEnd, ok := tracker.completedData.prevSet(endIdx); ok {
		start = prevEnd + 1
	}

	if tracker.indexProcessed[start] {
		return 0, 0, false
	}

	for i := start; i <= endIdx; i++ {
		if tracker.shredStatus[i] == 0 {
			return 0, 0, false
		}
	}

	return start, endIdx, true
}

func (a *Assembler) assemble(tracker *Tracker, triggerIndex uint32) [][]Entry {
	var batches [][]Entry
	idx := triggerIndex

	for {
		start, end, found := tracker.findRange(idx)
		if !found {
			break
		}

		segmentSize := end - start + 1
		segment := a.segmentBuffer[:segmentSize]

		allPresent := true
		for i := uint32(0); i < segmentSize; i++ {
			segment[i] = tracker.shredPointers[start+i]
			if segment[i] == nil {
				allPresent = false
				break
			}
		}
		if !allPresent {
			break
		}

		payload := a.concatPayload(segment)

		entries, err := parseEntriesFromShredPayload(payload)
		if err != nil {
			break
		}

		slot := segment[0].Slot
		for i := range entries {
			entries[i].Slot = slot
		}

		for i := start; i <= end; i++ {
			tracker.indexProcessed[i] = true
		}

		batches = append(batches, entries)

		idx = end + 1
		if idx > tracker.highestIndex {
			break
		}
	}

	return batches
}

func (a *Assembler) getOrCreateSlotState(slot uint64) *SlotState {

	if slot > a.CurrentSlot {
		a.CurrentSlot = slot
		if a.OnSlot != nil {
			a.OnSlot(slot)
		}
	}

	for i := uint32(0); i < a.slotCount; i++ {
		if a.slotKeys[i] == slot {
			return a.slotStates[i]
		}
	}

	if a.slotCount < MaxSlotsTracked {
		slotState := a.slotStates[a.slotCount]
		a.slotKeys[a.slotCount] = slot
		a.slotCount++

		a.resetSlotState(slotState)
		return slotState
	}

	slotState := a.slotStates[0]
	copy(a.slotStates[:], a.slotStates[1:])
	copy(a.slotKeys[:], a.slotKeys[1:])
	a.slotKeys[a.slotCount-1] = slot
	a.slotStates[a.slotCount-1] = slotState

	a.resetSlotState(slotState)
	return slotState
}

func (a *Assembler) resetSlotState(state *SlotState) {
	tracker := state.tracker

	// Release all pooled buffers referenced from the tracker and FEC sets.
	// releaseShred is idempotent (no-op once RawPayload is nil), so pointers
	// shared between the tracker and set.data are safe to hit twice.
	for i := tracker.lowestIndex; i <= tracker.highestIndex; i++ {
		if sh := tracker.shredPointers[i]; sh != nil {
			releaseShred(sh)
		}
		tracker.shredStatus[i] = 0
		tracker.shredPointers[i] = nil
		tracker.indexProcessed[i] = false
		tracker.completedData.clear(i)
	}

	for i := uint32(0); i < state.fecTouchedCnt; i++ {
		set := state.fecSets[state.fecTouched[i]]
		if set != nil {
			for j := range set.code {
				if sh := set.code[j]; sh != nil {
					releaseShred(sh)
					set.code[j] = nil
				}
			}
			for j := range set.data {
				if sh := set.data[j]; sh != nil {
					releaseShred(sh)
					set.data[j] = nil
				}
			}
		}
		state.fecSets[state.fecTouched[i]] = nil
	}

	tracker.lowestIndex = ^uint32(0)
	tracker.highestIndex = 0
	tracker.shredCount = 0
	state.fecTouchedCnt = 0
}

var errInvalidEntryPayload = errors.New("invalid shred entry payload")

func parseEntriesFromShredPayload(payload []byte) ([]Entry, error) {
	if len(payload) < 8 {
		return nil, errInvalidEntryPayload
	}

	numEntries := binary.LittleEndian.Uint64(payload[:8])
	if numEntries == 0 || numEntries > uint64(len(payload)-8)/48 {
		return nil, errInvalidEntryPayload
	}

	entries := make([]Entry, numEntries)
	off := 8
	for i := uint64(0); i < numEntries; i++ {
		var err error
		off, err = entries[i].unmarshal(payload, off)
		if err != nil {
			return nil, err
		}
	}

	return entries, nil
}

func (a *Assembler) pushRecovered(tracker *Tracker, recovered []*Shred) [][]Entry {
	var batches [][]Entry
	for _, sh := range recovered {
		if sh == nil || tracker.indexProcessed[sh.Index] {
			continue
		}
		if !a.updateTracker(sh, tracker) {
			continue
		}
		batches = append(batches, a.assemble(tracker, sh.Index)...)
	}
	return batches
}

func (a *Assembler) concatPayload(shreds []*Shred) []byte {
	total := 0
	for i := range shreds {
		total += len(shreds[i].Payload)
	}

	if cap(a.payloadBuffer) < total {
		a.payloadBuffer = make([]byte, total)
	} else {
		a.payloadBuffer = a.payloadBuffer[:total]
	}

	offset := 0
	for i := range shreds {
		offset += copy(a.payloadBuffer[offset:], shreds[i].Payload)
	}

	return a.payloadBuffer[:offset]
}
