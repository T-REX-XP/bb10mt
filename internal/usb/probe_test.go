package usb

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func probeTranscript(model uint32) (*scripted, *scripted) {
	metrics := make([]byte, 132)
	binary.LittleEndian.PutUint32(metrics[16:], model)
	boot := &scripted{responses: [][]byte{c0(2, 0, nil), c0(6, 1, metrics), c0(8, 2, nil), c0(0x10, 3, nil), frame(0, nil), frame(1, nil), frame(1, nil)}}
	for seq := uint16(0); seq <= 9; seq++ {
		boot.responses = append(boot.responses, c1(seq, nil), frame(1, nil))
	}
	boot.responses = append(boot.responses, frame(1, nil))
	loader := &scripted{responses: [][]byte{c0(8, 0, nil), c0(0x10, 1, nil), frame(0, nil), frame(2, channel2(0xd0, nil)), frame(2, nil), frame(2, channel2(0xd2, nil)), frame(2, nil), frame(2, channel2(0x80c7, nil)), frame(2, nil)}}
	return boot, loader
}

func TestProbeMultipleLoadersAndSkipIncompatible(t *testing.T) {
	const model = 0x8c00240a
	dir := t.TempDir()
	for _, name := range []string{"a.bin", "b.bin"} {
		if e := os.WriteFile(filepath.Join(dir, name), loaderFixture(model), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "c.bin"), loaderFixture(0xb600240a), 0600); e != nil {
		t.Fatal(e)
	}
	b1, l1 := probeTranscript(model)
	b2, l2 := probeTranscript(model)
	backend := &fakeBackend{transports: []*scripted{b1, l1, b2, l2}, infos: []DeviceInfo{{Bus: 2, Address: 3, Product: 1}, {Bus: 2, Address: 4, Product: 0x8001}, {Bus: 2, Address: 5, Product: 1}, {Bus: 2, Address: 6, Product: 0x8001}}}
	var results []ProbeResult
	e := ProbeLoaders(context.Background(), backend, Options{LoaderDirectory: dir, Bus: -1, Address: -1, Wait: time.Second, RunDelay: time.Nanosecond}, func(r ProbeResult) error { results = append(results, r); return nil })
	if e != nil || len(results) != 3 || backend.opened != 4 {
		t.Fatal(results, backend.opened, e)
	}
	if results[0].Status != "initialized-and-rebooted" || results[1].Status != "initialized-and-rebooted" || results[2].Status != "skipped" {
		t.Fatal(results)
	}
	for _, transcript := range []*scripted{b1, l1, b2, l2} {
		if len(transcript.responses) != 0 {
			t.Fatal("incomplete transcript")
		}
	}
}

func TestProbeStopsOnFailureAndBoundsCandidates(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "a.bin"), loaderFixture(0x8c00240a), 0600); e != nil {
		t.Fatal(e)
	}
	b, l := probeTranscript(0x8c00240a)
	b.responses = b.responses[:2] // fail before any loader is sent
	backend := &fakeBackend{transports: []*scripted{b, l}, infos: []DeviceInfo{{Product: 1}, {Product: 0x8001}}}
	if e := ProbeLoaders(context.Background(), backend, Options{LoaderDirectory: dir, Bus: -1, Address: -1}, func(ProbeResult) error { t.Fatal("reported success on failed transport"); return nil }); e == nil || backend.opened != 1 {
		t.Fatal(backend.opened, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := ProbeLoaders(ctx, &fakeBackend{}, Options{LoaderDirectory: dir}, func(ProbeResult) error { return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := probeCandidates(Options{LoaderDirectory: t.TempDir()}, nil); e == nil {
		t.Fatal("empty candidates accepted")
	}
}
