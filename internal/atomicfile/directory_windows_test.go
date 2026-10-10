package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPublishDirectoryWaitsForWindowsDirectoryHandle(t *testing.T) {
	root := t.TempDir()
	stage, output := filepath.Join(root, "stage"), filepath.Join(root, "output")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "checked.exe"), []byte("checked"), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	var closeOnce sync.Once
	closeHandle := func() { closeOnce.Do(func() { windows.CloseHandle(handle) }) }
	defer closeHandle()
	if err := os.Rename(stage, output); !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatal("expected directory-handle rename denial", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		closeHandle()
		close(released)
	}()
	err = PublishDirectory(stage, output)
	<-released
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "checked.exe"))
	if err != nil || string(data) != "checked" {
		t.Fatal(string(data), err)
	}
}
