//go:build linux

package shred

import (
	"context"
	"github.com/sparx7783/shred/xdp"
)

type XDPConfig = xdp.Config

func ListenXDP(ctx context.Context, cfg XDPConfig, fn func(packet []byte)) error {
	return xdp.Listen(ctx, cfg, fn)
}
