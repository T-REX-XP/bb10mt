package usb

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/bb10root/bb10mt/internal/qcfm"
)

func TestFlashValidatedSnapshotAndAcknowledgements(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "test.ufs")
	payload := bytes.Repeat([]byte{0x42}, 65536)
	os.WriteFile(raw, payload, 0600)
	stage := filepath.Join(dir, "stage")
	os.Mkdir(stage, 0700)
	inputs, e := PrepareFirmware(stage, []qcfm.Input{{Path: raw}}, 2)
	if e != nil {
		t.Fatal(e)
	}
	input := inputs[0]
	s := &scripted{}
	add := func(code uint16) { s.responses = append(s.responses, frame(2, channel2(code, nil)), frame(2, nil)) }
	add(0x39)
	blocks := (input.PayloadBytes + 0x3fec - 1) / 0x3fec
	for range blocks {
		add(0xdf)
	}
	add(0x4006)
	add(0x402e)
	report, e := NewProtocol(s).Flash(context.Background(), 0x8c00240a, input)
	if e != nil || int64(report.Blocks) != blocks {
		t.Fatal(report, e)
	}
	var restored []byte
	for i, b := range s.sent {
		_, p, e := ParseOuter(b)
		if e != nil {
			t.Fatal(e)
		}
		cmd, p, e := parseChannel2(p)
		if e != nil {
			t.Fatal(e)
		}
		switch {
		case i == 0:
			if cmd != 0x20ee || p[0] != 0x15 || p[1] != 0x28 {
				t.Fatal(p)
			}
		case int64(i) <= blocks:
			if cmd != 0xf7 || binary.LittleEndian.Uint32(p) != uint32(i-1) || int(binary.LittleEndian.Uint32(p[4:])) != len(p)-8 {
				t.Fatal(p)
			}
			restored = append(restored, p[8:]...)
		case int64(i) == blocks+1:
			if cmd != 0x40f9 || binary.LittleEndian.Uint16(p) != 560 || !bytes.Equal(p[2:], input.Trailer) {
				t.Fatal("signature changed")
			}
		default:
			if cmd != 0x40c0 {
				t.Fatal(cmd)
			}
		}
	}
	staged, _ := os.ReadFile(input.Path)
	if !bytes.Equal(restored, staged[:input.PayloadBytes]) {
		t.Fatal("payload changed")
	}
	// A changed snapshot is rejected before PreFlash, including an unsigned file
	// whose structure remains valid but whose payload no longer matches its hash.
	staged[100] ^= 1
	os.WriteFile(input.Path, staged, 0600)
	s = &scripted{}
	if _, e = NewProtocol(s).Flash(context.Background(), 0x8c00240a, input); e == nil || len(s.sent) != 0 {
		t.Fatal(e)
	}
}
func TestFlashStopsOnFirstRejectedBlock(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "test.ufs")
	os.WriteFile(raw, bytes.Repeat([]byte{1}, 65536), 0600)
	stage := filepath.Join(dir, "stage")
	os.Mkdir(stage, 0700)
	inputs, e := PrepareFirmware(stage, []qcfm.Input{{Path: raw}}, 2)
	if e != nil {
		t.Fatal(e)
	}
	s := &scripted{responses: [][]byte{frame(2, channel2(0x39, nil)), frame(2, nil), frame(2, channel2(0x15, nil))}}
	if _, e = NewProtocol(s).Flash(context.Background(), 0x8c00240a, inputs[0]); e == nil || len(s.sent) != 2 {
		t.Fatal(e, len(s.sent))
	}
}
func TestPrepareRejectsBadContainerAndUnknownRaw(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bad.qcfm", "unknown.bin"} {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte("mfcqbroken"), 0600)
		stage, _ := os.MkdirTemp(dir, "stage")
		if _, e := PrepareFirmware(stage, []qcfm.Input{{Path: path}}, 2); e == nil {
			t.Fatal(name)
		}
	}
}
