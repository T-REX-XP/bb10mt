package qnx6

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/bb10root/bb10mt/internal/binio"
)

// The BB10 fs-qnx6 lookup/readdir callbacks distinguish an empty inode with
// length zero (end of directory) from an empty inode with a retained length
// (deleted entry). This deliberately does not use the offline Entries reader.
func nativeVisibleInodes(raw []byte) map[uint32]bool {
	visible := map[uint32]bool{}
	for off := 0; off < len(raw); off += 32 {
		ino := binio.U32(raw, off)
		if ino == 0 {
			if raw[off+4] == 0 {
				break
			}
			continue
		}
		if ino != Missing {
			visible[ino] = true
		}
	}
	return visible
}

func TestRemovePreservesNativeVisibilityAcrossDirectoryBlocks(t *testing.T) {
	e, _ := editor(t)
	if err := e.Mkdir("/apps", false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 140; i++ {
		name := fmt.Sprintf("/apps/entry-%03d", i)
		if err := e.WriteFile(name, bytes.NewReader(nil), 0, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, index := range []int{0, 70, 139} {
		if err := e.Remove(fmt.Sprintf("/apps/entry-%03d", index), false); err != nil {
			t.Fatal(err)
		}
		n, _, err := e.Resolve("/apps")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := e.directoryBytes(n)
		if err != nil {
			t.Fatal(err)
		}
		visible := nativeVisibleInodes(raw)
		entries, err := e.Entries(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !visible[entry.Inode] {
				t.Fatalf("removing entry-%03d hid %s from the native reader", index, entry.Name)
			}
		}
	}
	if err := e.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryReaderDistinguishesDeletedEntryFromEOF(t *testing.T) {
	for _, eof := range []bool{false, true} {
		t.Run(fmt.Sprintf("eof=%t", eof), func(t *testing.T) {
			e, _ := editor(t)
			if err := e.Mkdir("/apps", false); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"a", "b"} {
				if err := e.WriteFile("/apps/"+name, bytes.NewReader(nil), 0, true); err != nil {
					t.Fatal(err)
				}
			}
			n, _, err := e.Resolve("/apps")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := e.directoryBytes(n)
			if err != nil {
				t.Fatal(err)
			}
			// a follows . and ..; b must stay visible after a legal tombstone.
			clear(raw[64:68])
			if eof {
				raw[68] = 0
			}
			if err := e.writeData(n, bytes.NewReader(raw), uint64(len(raw))); err != nil {
				t.Fatal(err)
			}
			entries, err := e.Entries(n)
			if eof {
				if err == nil || !strings.Contains(err.Error(), "after end-of-directory") {
					t.Fatalf("interior EOF accepted: entries=%v err=%v", entries, err)
				}
			} else if err != nil || len(entries) != 3 || entries[2].Name != "b" {
				t.Fatalf("legal deleted entry rejected: entries=%v err=%v", entries, err)
			}
		})
	}
}
