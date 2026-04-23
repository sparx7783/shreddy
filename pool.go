package shreddy

import "sync"

// rawPayloadPool recycles the per-shred backing buffer. All buffers handed out
// have capacity PacketDataSize; callers slice to the desired length.
var rawPayloadPool = sync.Pool{
	New: func() any {
		var b [PacketDataSize]byte
		return &b
	},
}

// getRawPayload returns a pooled slice of len n, cap PacketDataSize. Bytes
// past n are unspecified (may carry residue from a prior shred); callers must
// not read past what they have written.
func getRawPayload(n int) []byte {
	b := rawPayloadPool.Get().(*[PacketDataSize]byte)
	return b[:n]
}

// releaseShred returns sh.RawPayload to the pool if it originated from there.
// Recovered shreds (whose RawPayload is nil) and any externally-supplied
// buffers are left alone.
func releaseShred(sh *Shred) {
	if sh == nil {
		return
	}
	if cap(sh.RawPayload) != PacketDataSize {
		sh.RawPayload = nil
		sh.Payload = nil
		sh.ErasureShard = nil
		return
	}
	arr := (*[PacketDataSize]byte)(sh.RawPayload[:PacketDataSize])
	rawPayloadPool.Put(arr)
	sh.RawPayload = nil
	sh.Payload = nil
	sh.ErasureShard = nil
}
