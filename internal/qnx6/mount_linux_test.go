package qnx6

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bb10root/bb10mt/internal/binio"
)

func mountFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	image := filepath.Join(dir, "source.ufs")
	if e := Mkfs(image, 2048, 128, 4096); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(image, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	ed, e := NewEditor(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = ed.WriteFile("/payload", bytes.NewBufferString("original"), 8, true); e != nil {
		t.Fatal(e)
	}
	root, _ := ed.Inode(1)
	binio.LE.PutUint16(root.Raw[32:], 0x4000|0777)
	if e = ed.setNode(root); e != nil {
		t.Fatal(e)
	}
	if e = ed.Commit(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	return image, dir
}

func TestFuseMountedTransaction(t *testing.T) {
	if os.Getenv("BB10MT_FUSE_TEST") != "1" {
		t.Skip("set BB10MT_FUSE_TEST=1 for kernel FUSE integration")
	}
	for _, name := range []string{"readonly", "writable", "rollback"} {
		t.Run(name, func(t *testing.T) {
			writable, rollback := name != "readonly", name == "rollback"
			input, dir := mountFixture(t)
			before, _ := os.ReadFile(input)
			output := ""
			if writable {
				output = filepath.Join(dir, "out.ufs")
			}
			mp := filepath.Join(dir, "mount")
			os.Mkdir(mp, 0700)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Mount(ctx, input, output, mp, MountOptions{}, io.Discard) }()
			finished := false
			defer func() {
				cancel()
				if !finished {
					select {
					case e := <-done:
						if e != nil {
							t.Error(e)
						}
					case <-time.After(10 * time.Second):
						t.Error("mount did not stop")
					}
				}
			}()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if b, e := os.ReadFile(filepath.Join(mp, "payload")); e == nil && string(b) == "original" {
					break
				}
				select {
				case e := <-done:
					finished = true
					t.Fatalf("mount exited: %v", e)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("mount did not become ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			file := filepath.Join(mp, "created")
			var initial syscall.Statfs_t
			if e := syscall.Statfs(mp, &initial); e != nil {
				t.Fatal(e)
			}
			if !writable {
				if e := os.WriteFile(file, []byte("deny"), 0600); !errors.Is(e, syscall.EROFS) {
					t.Fatal(e)
				}
			} else {
				if e := os.WriteFile(file, []byte("changed"), 0640); e != nil {
					t.Fatal(e)
				}
				var updated syscall.Statfs_t
				if e := syscall.Statfs(mp, &updated); e != nil || updated.Bfree >= initial.Bfree || updated.Ffree >= initial.Ffree {
					t.Fatal(initial, updated, e)
				}
				if e := os.Mkdir(filepath.Join(mp, "dir"), 0755); e != nil {
					t.Fatal(e)
				}
				moved := filepath.Join(mp, "dir", "moved")
				if e := os.Rename(file, moved); e != nil {
					t.Fatal(e)
				}
				if e := os.Link(moved, filepath.Join(mp, "alias")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("dir/moved", filepath.Join(mp, "link")); e != nil {
					t.Fatal(e)
				}
				if b, e := os.ReadFile(filepath.Join(mp, "link")); e != nil || string(b) != "changed" {
					t.Fatal(string(b), e)
				}
				f, e := os.OpenFile(moved, os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.WriteAt([]byte("tail"), 10); e != nil {
					t.Fatal(e)
				}
				if e = f.Truncate(12); e != nil {
					t.Fatal(e)
				}
				if e = f.Sync(); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(filepath.Join(mp, "alias")); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(moved); !errors.Is(e, syscall.EBUSY) {
					t.Fatal("last open link", e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
				if rollback {
					if e = os.Remove(filepath.Join(mp, "dir")); e == nil {
						t.Fatal("removed nonempty directory")
					}
				}
			}
			cancel()
			select {
			case e := <-done:
				finished = true
				if (e != nil) != rollback {
					t.Fatal(e)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("unmount timeout")
			}
			after, _ := os.ReadFile(input)
			if !bytes.Equal(before, after) {
				t.Fatal("source modified")
			}
			if rollback {
				if _, e := os.Stat(output); !os.IsNotExist(e) {
					t.Fatal("failed transaction published output", e)
				}
				return
			}
			if writable {
				f, e := os.Open(output)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				st, _ := f.Stat()
				im, e := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
				if e != nil {
					t.Fatal(e)
				}
				report, e := im.Check()
				if e != nil || len(report.Errors) > 0 {
					t.Fatal(report, e)
				}
				n, _, e := im.Resolve("/dir/moved")
				if e != nil {
					t.Fatal(e)
				}
				var b bytes.Buffer
				if e = im.Data(n, &b); e != nil || !bytes.Equal(b.Bytes(), []byte("changed\x00\x00\x00ta")) {
					t.Fatal(b.Bytes(), e)
				}
			}
		})
	}
}
