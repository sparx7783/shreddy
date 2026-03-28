package shreddy

import (
	"encoding/binary"
	"errors"
)

const (
	MaxDataShredsPerSlot = 32768
	MaxSlotsTracked      = 64
	MaxEntriesPerBatch   = 1000
)

type Tracker struct {
	shredStatus    [MaxDataShredsPerSlot]uint8
	shredPointers  [MaxDataShredsPerSlot]*Shred
	indexProcessed [MaxDataShredsPerSlot]bool

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
	OnSlot      func(slot uint64) // called when a new highest slot is seen
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
		return nil
	}

	slotState := a.getOrCreateSlotState(sh.Slot)
	set, ok := a.addToFECSet(slotState, sh)
	if !ok {
		return nil
	}

	if sh.IsCode() {
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
	if set.recovered || tracker.indexProcessed[sh.Index] {
		return nil
	}

	if !a.updateTracker(sh, tracker) {
		return nil
	}

	if entries, ok := a.assemble(tracker, sh.Index); ok {
		return [][]Entry{entries}
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

func (a *Assembler) addToFECSet(slotState *SlotState, sh *Shred) (*FECSetState, bool) {
	fecSetIndex := sh.FECSetIndex
	set := slotState.fecSets[fecSetIndex]
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
			return nil, false
		}
		if set.data[rel] == nil {
			set.data[rel] = sh
			set.dataCount++
		}
		if sh.ErasureShard != nil {
			set.shardSize = len(sh.ErasureShard)
		}
		if sh.DataHeader.EndOfBatch() || sh.DataHeader.EndOfBlock() {
			set.numData = rel + 1
		}
		return set, true
	}

	if set.numData != 0 && set.numData != int(sh.CodeHeader.NumDataShreds) {
		return nil, false
	}
	if set.numCode != 0 && set.numCode != int(sh.CodeHeader.NumCodeShreds) {
		return nil, false
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
	}
	return set, true
}

func (a *Assembler) assemble(tracker *Tracker, triggerIndex uint32) ([]Entry, bool) {

	start, end, found := a.getSegment(tracker, triggerIndex)
	if !found {
		return nil, false
	}

	segmentSize := end - start + 1
	segment := a.segmentBuffer[:segmentSize]

	for i := uint32(0); i < segmentSize; i++ {
		segment[i] = tracker.shredPointers[start+i]
		if segment[i] == nil {
			return nil, false
		}
	}

	payload := a.concatPayload(segment)

	entries, err := parseEntriesFromShredPayload(payload)

	if err == nil {
		slot := segment[0].Slot
		for i := range entries {
			entries[i].Slot = slot
		}

		for i := start; i <= end; i++ {
			tracker.indexProcessed[i] = true
		}
	}

	return entries, err == nil
}

func (a *Assembler) getSegment(tracker *Tracker, index uint32) (start, end uint32, found bool) {

	if index >= MaxDataShredsPerSlot || tracker.shredStatus[index] == 0 {
		return 0, 0, false
	}

	end = index
	for end < tracker.highestIndex+1 {
		if tracker.indexProcessed[end] {
			return 0, 0, false
		}

		status := tracker.shredStatus[end]
		if status == 0 {
			return 0, 0, false
		}
		if status == 2 {
			break
		}
		end++
	}

	if tracker.shredStatus[end] != 2 {
		return 0, 0, false
	}

	start = index
	if index > 0 {
		for i := index - 1; ; i-- {
			status := tracker.shredStatus[i]
			if status == 2 {
				break
			}
			if status == 0 || tracker.indexProcessed[i] {
				break
			}
			start = i
			if i == 0 {
				break
			}
		}
	}

	return start, end, true
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

	for i := tracker.lowestIndex; i <= tracker.highestIndex; i++ {
		tracker.shredStatus[i] = 0
		tracker.shredPointers[i] = nil
		tracker.indexProcessed[i] = false
	}

	for i := uint32(0); i < state.fecTouchedCnt; i++ {
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
	if numEntries == 0 || numEntries > MaxEntriesPerBatch {
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
		if entries, ok := a.assemble(tracker, sh.Index); ok {
			batches = append(batches, entries)
		}
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
