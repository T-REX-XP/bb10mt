package usb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loaderFixture(model uint32) []byte {
	b := make([]byte, 10240)
	address, _ := LoaderAddress(model)
	binary.LittleEndian.PutUint32(b[4:], 0xd7d32d1f)
	binary.LittleEndian.PutUint32(b[8:], address)
	binary.LittleEndian.PutUint32(b[len(b)-8:], 0xd7c82d1f)
	return b
}
func TestLoaderValidationAndINI(t *testing.T) {
	const model = 0x8c00240a
	b := loaderFixture(model)
	if a, e := ValidateLoader(b, model); e != nil || a != 0x80200000 {
		t.Fatal(a, e)
	}
	for _, bad := range [][]byte{b[:20], append([]byte{}, b...), append([]byte{}, b...), append([]byte{}, b...)} {
		switch len(bad) {
		case 20:
		default:
			if bad[4] == 0x1f {
				bad[4] = 0
			} else {
				bad[8] ^= 1
			}
		}
		if _, e := ValidateLoader(bad, model); e == nil {
			t.Fatal("invalid loader")
		}
	}
	erased := bytes.Clone(b)
	copy(erased[len(b)-144:len(b)-16], bytes.Repeat([]byte{0xff}, 128))
	if _, e := ValidateLoader(erased, model); e == nil {
		t.Fatal("erased signature")
	}
	if _, e := LoaderAddress(0x1234); e == nil {
		t.Fatal("unknown address")
	}
	if a, _ := LoaderAddress(0xb600240a); a != 0x0dd00000 {
		t.Fatal(a)
	}
	for _, bad := range []string{"[Loaders]\n8c00240a=../escape", "[Loaders]\n8c00240a=abc\n8C00240A=dup", "[Loaders]\ninvalid=abc"} {
		if _, e := LoaderMap(strings.NewReader(bad)); e == nil {
			t.Fatal(bad)
		}
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "bb10mt.ini")
	os.WriteFile(config, []byte("[Other]\nx=y\n[Loaders]\n8c00240a=LDR_01\n"), 0600)
	os.WriteFile(filepath.Join(dir, "LDR_01.bin"), b, 0600)
	if got, name, e := SelectLoader(dir, "", config, model); e != nil || !bytes.Equal(got, b) || filepath.Base(name) != "LDR_01.bin" {
		t.Fatal(name, e)
	}
}

type fakeBackend struct {
	transports []*scripted
	infos      []DeviceInfo
	opened     int
	err        error
}

func (b *fakeBackend) Devices() ([]DeviceInfo, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.opened >= len(b.infos) {
		return nil, nil
	}
	return []DeviceInfo{b.infos[b.opened]}, nil
}
func (b *fakeBackend) OpenDevice(_ []uint16, _, _ int) (Transport, DeviceInfo, error) {
	if b.err != nil {
		return nil, DeviceInfo{}, b.err
	}
	t, i := b.transports[b.opened], b.infos[b.opened]
	b.opened++
	return t, i, nil
}
func TestFullBootAndLoaderTranscript(t *testing.T) {
	const model = 0x8c00240a
	metrics := make([]byte, 132)
	binary.LittleEndian.PutUint32(metrics[4:], 1)
	binary.LittleEndian.PutUint32(metrics[12:], 3)
	binary.LittleEndian.PutUint32(metrics[16:], model)
	copy(metrics[20:], "Z30")
	boot := &scripted{responses: [][]byte{c0(2, 0, nil), c0(6, 1, metrics), c0(8, 2, nil), c0(0x10, 3, nil), frame(0, nil), frame(1, nil), frame(1, nil)}}
	for seq := uint16(0); seq <= 9; seq++ {
		boot.responses = append(boot.responses, c1(seq, nil), frame(1, nil))
	}
	boot.responses = append(boot.responses, frame(1, nil))
	loader := &scripted{responses: [][]byte{c0(8, 0, nil), c0(0x10, 1, nil), frame(0, nil), frame(2, channel2(0xd0, nil)), frame(2, nil), frame(2, channel2(0xd2, []byte("regions"))), frame(2, nil)}}
	backend := &fakeBackend{transports: []*scripted{boot, loader}, infos: []DeviceInfo{{Bus: 2, Address: 3, Product: 1}, {Bus: 2, Address: 4, Product: 0x8001}}}
	file := filepath.Join(t.TempDir(), "loader.bin")
	data := loaderFixture(model)
	os.WriteFile(file, data, 0600)
	o := Options{Bus: -1, Address: -1, LoaderFile: file, Wait: time.Second, RunDelay: time.Nanosecond}
	s, e := OpenBoot(context.Background(), backend, o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Info.ModelID != model || s.Info.HardwareName != "Z30" {
		t.Fatal(s.Info)
	}
	if e = s.StartLoader(context.Background(), backend, o); e != nil {
		t.Fatal(e)
	}
	if backend.opened != 2 || s.Device.Address != 4 || len(boot.responses) != 0 || len(loader.responses) != 0 {
		t.Fatal(backend.opened, len(boot.responses), len(loader.responses))
	}
	var loaded []byte
	for _, sent := range boot.sent {
		ch, p, _ := ParseOuter(sent)
		if ch != 1 || len(p) == 2 {
			continue
		}
		_, p, e := parseChannel1(p)
		if e != nil {
			t.Fatal(e)
		}
		if binary.LittleEndian.Uint16(p) == 0xf004 {
			if binary.LittleEndian.Uint32(p[2:]) != 0x80200000+uint32(len(loaded)) {
				t.Fatal("wrong RAM address")
			}
			loaded = append(loaded, p[10:]...)
		}
	}
	if !bytes.Equal(loaded, data) {
		t.Fatal("RAM payload changed")
	}
}
func TestBootErrorsAndCancellation(t *testing.T) {
	backend := &fakeBackend{err: errors.New("access denied")}
	if _, e := OpenBoot(context.Background(), backend, Options{}); e == nil || backend.opened != 0 {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := OpenBoot(ctx, &fakeBackend{}, Options{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s := &scripted{responses: [][]byte{c0(2, 0, nil), c0(6, 1, []byte{1})}}
	backend = &fakeBackend{transports: []*scripted{s}, infos: []DeviceInfo{{Product: 1}}}
	if _, e := OpenBoot(context.Background(), backend, Options{Bus: -1, Address: -1}); e == nil {
		t.Fatal("short metrics")
	}
}
