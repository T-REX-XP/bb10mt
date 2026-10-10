package usb

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestLegacyLibusbABI(t *testing.T) {
	// libusb-1.0 public C descriptors use natural alignment, not packed layout.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("release targets are 64-bit")
	}
	for _, tc := range []struct {
		name      string
		got, want uintptr
	}{
		{"device", unsafe.Sizeof(deviceDescriptor{}), 18}, {"endpoint", unsafe.Sizeof(endpointDescriptor{}), 32},
		{"interface descriptor", unsafe.Sizeof(interfaceDescriptor{}), 40}, {"interface", unsafe.Sizeof(usbInterface{}), 16}, {"config", unsafe.Sizeof(configDescriptor{}), 40},
		{"endpoint extra", unsafe.Offsetof(endpointDescriptor{}.Extra), 16}, {"interface endpoints", unsafe.Offsetof(interfaceDescriptor{}.Endpoint), 16}, {"config interfaces", unsafe.Offsetof(configDescriptor{}.Interface), 16},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s: %d != %d", tc.name, tc.got, tc.want)
		}
	}
}
func fakeDevice(bulk func(unsafe.Pointer, byte, unsafe.Pointer, int32, *int32, uint32) int32) *Device {
	handle := new(byte)
	return &Device{context: &Context{a: &api{bulk: bulk}}, handle: unsafe.Pointer(handle), In: 0x82, Out: 2, Interface: -1}
}
func TestBulkReassemblesFragmentsAndCoalescedFrames(t *testing.T) {
	a, b := frame(0, []byte{1, 2, 3, 4}), frame(2, channel2(1, nil))
	stream := append(bytes.Clone(a), b...)
	pieces := [][]byte{stream[:1], stream[1:3], stream[3:7], stream[7:]}
	calls := 0
	d := fakeDevice(func(_ unsafe.Pointer, ep byte, p unsafe.Pointer, n int32, out *int32, _ uint32) int32 {
		if ep != 0x82 || len(pieces) == 0 {
			t.Fatal("unexpected read")
		}
		part := pieces[0]
		pieces = pieces[1:]
		copy(unsafe.Slice((*byte)(p), int(n)), part)
		*out = int32(len(part))
		calls++
		return 0
	})
	if got, e := d.Receive(); e != nil || !bytes.Equal(got, a) {
		t.Fatal(got, e)
	}
	if got, e := d.Receive(); e != nil || !bytes.Equal(got, b) || calls != 4 {
		t.Fatal(got, e, calls)
	}
}
func TestBulkShortWriteAndReadErrors(t *testing.T) {
	d := fakeDevice(func(_ unsafe.Pointer, _ byte, _ unsafe.Pointer, n int32, out *int32, _ uint32) int32 {
		*out = n - 1
		return 0
	})
	if e := d.Send([]byte{1, 2}); e == nil {
		t.Fatal("short write")
	}
	for _, code := range []int32{-7, 0} {
		d = fakeDevice(func(_ unsafe.Pointer, _ byte, _ unsafe.Pointer, _ int32, out *int32, _ uint32) int32 {
			*out = 0
			return code
		})
		if _, e := d.Receive(); e == nil {
			t.Fatal("read error")
		}
	}
	d = fakeDevice(nil)
	d.buffer = []byte{0, 0, 0, 0}
	if _, e := d.Receive(); e == nil {
		t.Fatal("zero frame")
	}
	d.handle = nil
	if e := d.Send([]byte{1}); e == nil {
		t.Fatal("closed write")
	}
	if _, e := d.Receive(); e == nil {
		t.Fatal("closed read")
	}
}
func TestCleanupReportsReleaseFailureAndClosesOnce(t *testing.T) {
	d := fakeDevice(nil)
	d.Interface = 1
	closes, releases := 0, 0
	d.context.a.release = func(unsafe.Pointer, int32) int32 { releases++; return -1 }
	d.context.a.close = func(unsafe.Pointer) { closes++ }
	if e := d.Close(); e == nil {
		t.Fatal("lost release error")
	}
	if e := d.Close(); e != nil || closes != 1 || releases != 1 {
		t.Fatal(e, closes, releases)
	}
}
