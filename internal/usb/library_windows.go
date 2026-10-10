package usb

import "syscall"

func openLibrary(path string) (func(string) (uintptr, error), func() error, error) {
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, nil, err
	}
	return func(name string) (uintptr, error) {
		proc, err := dll.FindProc(name)
		if err != nil {
			return 0, err
		}
		return proc.Addr(), nil
	}, dll.Release, nil
}
