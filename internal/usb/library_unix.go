//go:build linux || darwin

package usb

import "github.com/ebitengine/purego"

func openLibrary(path string) (func(string) (uintptr, error), func() error, error) {
	h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, nil, err
	}
	return func(name string) (uintptr, error) { return purego.Dlsym(h, name) }, func() error { return purego.Dlclose(h) }, nil
}
