//go:build linux

package shreddy

import (
	"context"

	"github.com/sparx7783/shred/xdp"
)

type XDPConfig = xdp.Config

func ListenXDP(ctx context.Context, cfg XDPConfig, fn func(packet []byte)) error {
	return xdp.Listen(ctx, cfg, fn)
}
