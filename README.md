# shreddy

I have open-sourced the shred decoder I wrote for my personal bot since there's not much in go for shred support.

The library implementation is minimal because originally it was built directly into my bot, and is designed for use with sniping/hft/trading bots, therefore it does not
support merkle shred proof verification, verifying the signature chain, and also does not support legacy shreds. 

Some of the code was taken from [radiance](https://github.com/firedancer-io/radiance) which was written by firedancer.


## Notes

- Shreddy is synchronous, I wouldn't try to run async decoders without creating a separate assembler and on different ports, but mostly untested. 
- Async support is probably not coming since on a single go routine/thread it can handle multiple shred providers worth of traffic, but you can always open a PR / maybe I'll add it in the future if needed.
- XDP implementation might need some work, currently to maintain sync support it only supports streaming from one RX Queue, you can direct all port traffic to a single queue by configuring NIC flow steering like this `sudo ethtool -N ens18 flow-type udp4 dst-port 7777 action 0` which would set all rx traffic to queue 0 on port 7777.
- `ZeroCopy: true` attempts AF_XDP zerocopy first and falls back to copy mode if unsupported by the NIC/driver.


## Features

- UDP listener
- Linux XDP listener
- Merkle shred decoding
- FEC recovery for missing data shreds
- entry extraction from assembled shred payloads
- Current Slot updates for leader tracking / whatever else you need it for

## Installation

```bash
go get github.com/sparx7783/shred
```

## Quick Start

### Decode shreds from UDP

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/sparx7783/shred"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	asm := shred.NewAssembler()

	// Optional: track the latest slot for leader scheduling
	asm.OnSlot = func(slot uint64) {
		fmt.Printf("new slot: %d\n", slot)
	}

	err := shred.ListenUDP(ctx, 7777, func(packet []byte) {
		sh := shred.NewShredFromSerialized(packet)
		if !sh.Ok() {
			return
		}

		for _, batch := range asm.Push(&sh) {
			for _, entry := range batch {
				log.Printf("slot=%d txns=%d\n", entry.Slot, len(entry.TxBytes))
				for _, txBytes := range entry.TxBytes {
					// txBytes is the raw serialized transaction.
					// Decode it with your own tx parser.
					_ = txBytes
				}
			}
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

### Decode shreds from XDP

```go
package main

import (
	"context"
	"log"
    
	"github.com/sparx7783/shred"
)

func main() {
	ctx := context.Background()
	asm := shred.NewAssembler()

	cfg := shred.XDPConfig{
		Interface: "eth0",
		Port:      7777,
		RXQueue:   0,
		NumFrames: 8192,
		FrameSize: 2048,
		ZeroCopy:  true,
	}

	err := shred.ListenXDP(ctx, cfg, func(packet []byte) {
		sh := shred.NewShredFromSerialized(packet)
		if !sh.Ok() {
			return
		}

		for _, batch := range asm.Push(&sh) {
			for _, entry := range batch {
				log.Printf("slot=%d txns=%d\n", entry.Slot, len(entry.TxBytes))
				for _, txBytes := range entry.TxBytes {
					// txBytes is the raw serialized transaction.
					// Decode it with your own tx parser.
					_ = txBytes
				}
			}
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

## License

See [LICENSE](LICENSE).
