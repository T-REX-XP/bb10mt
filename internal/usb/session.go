package usb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Backend interface {
	Devices() ([]DeviceInfo, error)
	OpenDevice(products []uint16, bus, address int) (Transport, DeviceInfo, error)
}

func (c *Context) OpenDevice(products []uint16, bus, address int) (Transport, DeviceInfo, error) {
	d, e := c.Open(products, bus, address)
	if e != nil {
		return nil, DeviceInfo{}, e
	}
	return d, d.Info, nil
}

type Options struct {
	LoaderDirectory, LoaderFile, Config, LoaderArchive, Password string
	Bus, Address                                                 int
	Wait, RunDelay                                               time.Duration
}
type BootInfo struct {
	ModelID        uint32 `json:"modelID"`
	Version        uint32 `json:"version"`
	BootROMVersion uint32 `json:"bootROMVersion"`
	HardwareName   string `json:"hardwareName,omitempty"`
	BuildUser      string `json:"buildUser,omitempty"`
	BuildDate      string `json:"buildDate,omitempty"`
	BuildTime      string `json:"buildTime,omitempty"`
}

func ParseBootInfo(b []byte) (BootInfo, error) {
	var i BootInfo
	if len(b) < 20 {
		return i, fmt.Errorf("truncated BootROM metrics")
	}
	b = b[4:]
	i.Version = binary.LittleEndian.Uint32(b)
	i.BootROMVersion = binary.LittleEndian.Uint32(b[8:])
	i.ModelID = binary.LittleEndian.Uint32(b[12:])
	if i.ModelID == 0 {
		return i, fmt.Errorf("missing BootROM model ID")
	}
	text := func(start, end int) string {
		if len(b) < end {
			return ""
		}
		s := string(b[start:end])
		s, _, _ = strings.Cut(s, "\x00")
		return strings.TrimSpace(s)
	}
	i.HardwareName = text(16, 80)
	i.BuildUser = text(80, 96)
	i.BuildDate = text(96, 112)
	i.BuildTime = text(112, 128)
	return i, nil
}

type Session struct {
	P      *Protocol
	Info   BootInfo
	Device DeviceInfo
	Loader string
}

func (s *Session) Close() error {
	if s.P == nil {
		return nil
	}
	e := s.P.IO.Close()
	s.P = nil
	return e
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func waitOpen(ctx context.Context, backend Backend, products []uint16, bus, address int) (Transport, DeviceInfo, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, DeviceInfo{}, e
		}
		infos, e := backend.Devices()
		if e != nil {
			return nil, DeviceInfo{}, e
		}
		matches := 0
		for _, i := range infos {
			if bus >= 0 && int(i.Bus) != bus || address >= 0 && int(i.Address) != address {
				continue
			}
			for _, product := range products {
				if i.Product == product {
					matches++
					break
				}
			}
		}
		if matches > 1 {
			return nil, DeviceInfo{}, fmt.Errorf("multiple matching USB devices; select --bus/--address")
		}
		if matches == 1 {
			return backend.OpenDevice(products, bus, address)
		}
		if e = pause(ctx, 100*time.Millisecond); e != nil {
			return nil, DeviceInfo{}, e
		}
	}
}

// OpenBoot opens the existing boot ROM mode. Entering this mode from the normal
// OS is explicit through RebootToBootROM; no access failure triggers a reboot.
func OpenBoot(ctx context.Context, backend Backend, o Options) (s *Session, err error) {
	if o.Wait <= 0 {
		o.Wait = 30 * time.Second
	}
	wait, cancel := context.WithTimeout(ctx, o.Wait)
	defer cancel()
	io, info, e := waitOpen(wait, backend, []uint16{1}, o.Bus, o.Address)
	if e != nil {
		return nil, e
	}
	s = &Session{P: NewProtocol(io), Device: info}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
			s = nil
		}
	}()
	cmd, _, e := s.P.Channel0(1, []byte{0x14, 5, 0x83, 0x19, 0, 0, 0, 0})
	if e != nil {
		return s, e
	}
	if cmd != 2 {
		return s, fmt.Errorf("BootROM ping returned 0x%02x", cmd)
	}
	cmd, b, e := s.P.Channel0(5, []byte{0xd0, 7, 2, 0})
	if e != nil {
		return s, e
	}
	if cmd != 6 {
		return s, fmt.Errorf("BootROM metrics returned 0x%02x", cmd)
	}
	s.Info, e = ParseBootInfo(b)
	return s, e
}
func RebootToBootROM(backend Backend, o Options) (err error) {
	t, _, e := backend.OpenDevice(nil, o.Bus, o.Address)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, t.Close()) }()
	_, _, err = NewProtocol(t).Channel0(3, nil)
	return err
}
func (s *Session) PrepareBoot(ctx context.Context, password string) error {
	if e := s.P.SetMode(1); e != nil {
		return e
	}
	if e := s.P.Password(ctx, password); e != nil {
		return e
	}
	if e := s.P.Switch(); e != nil {
		return e
	}
	_, e := s.P.BootCommand(0xf001, nil)
	return e
}
func (s *Session) StartLoader(ctx context.Context, backend Backend, o Options) error {
	data, name, e := SelectLoaderWithArchive(o.LoaderDirectory, o.LoaderFile, o.Config, o.LoaderArchive, s.Info.ModelID)
	if e != nil {
		return e
	}
	return s.startLoaderData(ctx, backend, o, data, name)
}

func (s *Session) startLoaderData(ctx context.Context, backend Backend, o Options, data []byte, name string) error {
	address, e := ValidateLoader(data, s.Info.ModelID)
	if e != nil {
		return e
	}
	if e = s.PrepareBoot(ctx, o.Password); e != nil {
		return e
	}
	chunk := 2024
	if address == 0x80100000 {
		chunk = 260
	}
	if e = s.P.Load(ctx, address, data, chunk); e != nil {
		return e
	}
	if e = pause(ctx, 50*time.Millisecond); e != nil {
		return e
	}
	if e = s.P.Run(address); e != nil {
		return e
	}
	if e = s.Close(); e != nil {
		return e
	}
	delay := o.RunDelay
	if delay <= 0 {
		delay = time.Second
	}
	if e = pause(ctx, delay); e != nil {
		return e
	}
	wait := o.Wait
	if wait <= 0 {
		wait = 30 * time.Second
	}
	w, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	io, info, e := waitOpen(w, backend, []uint16{0x8001}, int(s.Device.Bus), -1)
	if e != nil {
		return e
	}
	s.P = NewProtocol(io)
	s.Device = info
	s.Loader = name
	if e = s.P.SetMode(2); e != nil {
		return e
	}
	if e = s.P.Password(ctx, o.Password); e != nil {
		return e
	}
	if e = s.P.DrainLog(); e != nil {
		return e
	}
	_, e = s.P.Channel2(0xb4, nil, 0xd2)
	return e
}

type LoaderInfo struct {
	Boot             BootInfo `json:"boot"`
	Loader           string   `json:"loader"`
	PIN              uint32   `json:"pin"`
	BSN              uint32   `json:"bsn"`
	VendorID         uint16   `json:"vendorID"`
	FlashRegions     []byte   `json:"flashRegions"`
	MCT              []byte   `json:"mct"`
	OS               []byte   `json:"osMetrics"`
	DRAM             []byte   `json:"dram"`
	HardwareOverride []byte   `json:"hardwareOverride"`
	BlockedOS        []byte   `json:"blockedOS"`
	BlockedRadio     []byte   `json:"blockedRadio"`
}

func (s *Session) ReadInfo() (LoaderInfo, error) {
	result := LoaderInfo{Boot: s.Info, Loader: s.Loader}
	for _, q := range []struct {
		cmd, want uint16
		min       int
		apply     func([]byte)
	}{
		{0xe7, 0xd1, 4, func(b []byte) { result.PIN = binary.LittleEndian.Uint32(b) }},
		{0xea, 0xfc, 4, func(b []byte) { result.BSN = binary.LittleEndian.Uint32(b) }},
		{0xdb, 0xcb, 4, func(b []byte) { result.VendorID = binary.LittleEndian.Uint16(b[2:]) }},
		{0xb4, 0xd2, 0, func(b []byte) { result.FlashRegions = b }}, {0xd9, 0xc9, 0, func(b []byte) { result.MCT = b }},
		{0xd8, 0xc8, 0, func(b []byte) { result.OS = b }}, {0xbf, 0xd9, 0, func(b []byte) { result.DRAM = b }},
		{0xbd, 0xbe, 0, func(b []byte) { result.HardwareOverride = b }},
		{0xec, 0xfd, 0, func(b []byte) { result.BlockedOS = b }}, {0xed, 0xfe, 0, func(b []byte) { result.BlockedRadio = b }},
	} {
		b, e := s.P.Channel2(q.cmd, nil, q.want)
		if e != nil {
			return result, e
		}
		if len(b) < q.min {
			return result, fmt.Errorf("short info response for 0x%04x", q.cmd)
		}
		q.apply(b)
	}
	return result, nil
}
func (s *Session) Reboot() error { _, e := s.P.Channel2(0x80ef, nil, 0x80c7); return e }
