//go:build linux

package xdp

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel shredFilter bpf/shred_filter.c -- -I/usr/include -O2

type Config struct {
	Interface string
	Port      uint16
	RXQueue   int
	NumFrames int
	FrameSize int
	ZeroCopy  bool
}

func (c *Config) defaults() {
	if c.NumFrames == 0 {
		c.NumFrames = 8192
	}
	if c.FrameSize == 0 {
		c.FrameSize = 2048
	}
}

const (
	ethHdrLen = 14
	udpHdrLen = 8
)

func ipv4UDPPayloadOffset(frame []byte) int {
	if len(frame) < ethHdrLen+20+udpHdrLen {
		return -1
	}
	ihl := int(frame[ethHdrLen] & 0x0F)
	if ihl < 5 {
		return -1
	}
	offset := ethHdrLen + ihl*4 + udpHdrLen
	if offset > len(frame) {
		return -1
	}
	return offset
}

type Objects = shredFilterObjects

func LoadBPFObjects(opts *ebpf.CollectionOptions) (*Objects, error) {
	objs := &Objects{}
	if err := loadShredFilterObjects(objs, opts); err != nil {
		return nil, err
	}
	return objs, nil
}

func Listen(ctx context.Context, cfg Config, fn func(packet []byte)) error {
	cfg.defaults()
	if cfg.Interface == "" {
		return fmt.Errorf("interface required")
	}
	if cfg.RXQueue < 0 {
		return fmt.Errorf("rx queue must be >= 0")
	}
	if cfg.NumFrames <= 0 || cfg.NumFrames&(cfg.NumFrames-1) != 0 {
		return fmt.Errorf("num frames must be a power of two, got %d", cfg.NumFrames)
	}
	if cfg.FrameSize <= 0 {
		return fmt.Errorf("frame size must be > 0")
	}

	objs, err := LoadBPFObjects(nil)
	if err != nil {
		return fmt.Errorf("load bpf: %w", err)
	}
	defer objs.Close()

	if err := objs.TargetPort.Put(uint32(0), cfg.Port); err != nil {
		return fmt.Errorf("set target_port: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", cfg.Interface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpShredFilter,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}
	defer xdpLink.Close()

	sock, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("af_xdp socket: %w", err)
	}
	defer unix.Close(sock)

	umemSize := cfg.NumFrames * cfg.FrameSize
	umemBuf, err := unix.Mmap(-1, 0, umemSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap umem: %w", err)
	}
	defer unix.Munmap(umemBuf)

	umemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&umemBuf[0]))),
		Len:      uint64(umemSize),
		Size:     uint32(cfg.FrameSize),
		Headroom: 0,
	}
	if err := setsockoptUmemReg(sock, &umemReg); err != nil {
		return fmt.Errorf("umem reg: %w", err)
	}

	ringSize := cfg.NumFrames
	for _, opt := range []int{unix.XDP_UMEM_FILL_RING, unix.XDP_UMEM_COMPLETION_RING} {
		if err := unix.SetsockoptInt(sock, unix.SOL_XDP, opt, ringSize); err != nil {
			return fmt.Errorf("set ring size %d: %w", opt, err)
		}
	}
	if err := unix.SetsockoptInt(sock, unix.SOL_XDP, unix.XDP_RX_RING, ringSize); err != nil {
		return fmt.Errorf("set rx ring: %w", err)
	}

	offsets, err := getXDPMmapOffsets(sock)
	if err != nil {
		return fmt.Errorf("mmap offsets: %w", err)
	}

	fillMap, err := unix.Mmap(sock, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.Fill.Desc+uint64(ringSize)*8),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap fill: %w", err)
	}
	defer unix.Munmap(fillMap)

	fillProd := (*uint32)(unsafe.Pointer(&fillMap[offsets.Fill.Producer]))
	fillDescs := unsafe.Pointer(&fillMap[offsets.Fill.Desc])

	rxMap, err := unix.Mmap(sock, unix.XDP_PGOFF_RX_RING,
		int(offsets.RX.Desc+uint64(ringSize)*uint64(unsafe.Sizeof(unix.XDPDesc{}))),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap rx: %w", err)
	}
	defer unix.Munmap(rxMap)

	rxProd := (*uint32)(unsafe.Pointer(&rxMap[offsets.RX.Producer]))
	rxCons := (*uint32)(unsafe.Pointer(&rxMap[offsets.RX.Consumer]))
	rxDescs := unsafe.Pointer(&rxMap[offsets.RX.Desc])

	compMap, err := unix.Mmap(sock, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.Completion.Desc+uint64(ringSize)*8),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap comp: %w", err)
	}
	defer unix.Munmap(compMap)

	mask := uint32(ringSize - 1)

	for i := 0; i < ringSize; i++ {
		*(*uint64)(unsafe.Add(fillDescs, i*8)) = uint64(i * cfg.FrameSize)
	}
	*fillProd = uint32(ringSize)

	bindFlags := uint16(unix.XDP_COPY)
	if cfg.ZeroCopy {
		bindFlags = unix.XDP_ZEROCOPY
	}
	sa := unix.SockaddrXDP{
		Flags:   bindFlags,
		Ifindex: uint32(iface.Index),
		QueueID: uint32(cfg.RXQueue),
	}
	if err := unix.Bind(sock, &sa); err != nil {
		if !cfg.ZeroCopy {
			return fmt.Errorf("bind xdp: %w", err)
		}
		sa.Flags = unix.XDP_COPY
		if err = unix.Bind(sock, &sa); err != nil {
			return fmt.Errorf("bind xdp: %w", err)
		}
	}

	if err := objs.XskMap.Put(uint32(cfg.RXQueue), uint32(sock)); err != nil {
		return fmt.Errorf("xsk_map put: %w", err)
	}

	pollFds := []unix.PollFd{{Fd: int32(sock), Events: unix.POLLIN}}
	cons := uint32(0)
	fillProdLocal := uint32(ringSize)

	for {
		if ctx.Err() != nil {
			return nil
		}
		*fillProd = fillProdLocal

		if _, err := unix.Poll(pollFds, 100); err != nil && err != unix.EINTR {
			return fmt.Errorf("poll: %w", err)
		}

		prod := *rxProd
		for cons != prod {
			idx := cons & mask
			desc := (*unix.XDPDesc)(unsafe.Add(rxDescs, uintptr(idx)*unsafe.Sizeof(unix.XDPDesc{})))

			frame := umemBuf[desc.Addr : desc.Addr+uint64(desc.Len)]
			if off := ipv4UDPPayloadOffset(frame); off >= 0 && off < len(frame) {
				fn(frame[off:])
			}

			fillIdx := fillProdLocal & mask
			*(*uint64)(unsafe.Add(fillDescs, int(fillIdx)*8)) = desc.Addr
			fillProdLocal++
			cons++
		}
		*rxCons = cons
	}
}

func setsockoptUmemReg(sock int, reg *unix.XDPUmemReg) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(sock),
		unix.SOL_XDP,
		unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(reg)),
		unsafe.Sizeof(*reg), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

type xdpMmapOffsets struct {
	RX         xdpRingOffsets
	TX         xdpRingOffsets
	Fill       xdpRingOffsets
	Completion xdpRingOffsets
}

type xdpRingOffsets struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

func getXDPMmapOffsets(sock int) (*xdpMmapOffsets, error) {
	var offsets xdpMmapOffsets
	size := uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(sock),
		unix.SOL_XDP,
		unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &offsets, nil
}
