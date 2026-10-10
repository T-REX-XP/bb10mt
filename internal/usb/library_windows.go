package usb

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openLibrary(path string) (func(string) (uintptr, error), func() error, error) {
	flags := uintptr(windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	if filepath.Base(path) != path {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, nil, err
		}
		path = absolute
		flags |= windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
	}
	handle, err := windows.LoadLibraryEx(path, 0, flags)
	if err != nil {
		return nil, nil, err
	}
	return func(name string) (uintptr, error) {
		return windows.GetProcAddress(handle, name)
	}, func() error { return windows.FreeLibrary(handle) }, nil
}
