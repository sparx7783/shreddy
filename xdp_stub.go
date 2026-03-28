//go:build !linux

package shreddy

import (
	"context"
	"fmt"
	"runtime"
)

type XDPConfig struct {
	Interface string
	Port      uint16
	RXQueue   int
	NumFrames int
	FrameSize int
	ZeroCopy  bool
}

func ListenXDP(ctx context.Context, cfg XDPConfig, fn func(packet []byte)) error {
	return fmt.Errorf("XDP not supported on %s", runtime.GOOS)
}
