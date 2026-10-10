package usb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// All C ABI interaction is confined to this file. Only pointers to C-owned
// descriptor trees are converted to slices, with counts checked first.
type deviceDescriptor struct {
	Length, Type                                        byte
	USB                                                 uint16
	Class, Subclass, Protocol, Packet                   byte
	Vendor, Product, Device                             uint16
	Manufacturer, ProductString, Serial, Configurations byte
}
type endpointDescriptor struct {
	Length, Type, Address, Attributes byte
	Packet                            uint16
	Interval, Refresh, Synch          byte
	Extra                             unsafe.Pointer
	ExtraLength                       int32
}
type interfaceDescriptor struct {
	Length, Type, Number, Alternate, Endpoints, Class, Subclass, Protocol, String byte
	Endpoint                                                                      *endpointDescriptor
	Extra                                                                         unsafe.Pointer
	ExtraLength                                                                   int32
}
type usbInterface struct {
	Alternate *interfaceDescriptor
	Count     int32
}
type configDescriptor struct {
	Length, Type                                 byte
	Total                                        uint16
	Interfaces, Value, String, Attributes, Power byte
	Interface                                    *usbInterface
	Extra                                        unsafe.Pointer
	ExtraLength                                  int32
}

type api struct {
	init         func(*unsafe.Pointer) int32
	exit         func(unsafe.Pointer)
	list         func(unsafe.Pointer, *unsafe.Pointer) int64
	freeList     func(unsafe.Pointer, int32)
	descriptor   func(unsafe.Pointer, *deviceDescriptor) int32
	open         func(unsafe.Pointer, *unsafe.Pointer) int32
	close        func(unsafe.Pointer)
	getConfig    func(unsafe.Pointer, *int32) int32
	setConfig    func(unsafe.Pointer, int32) int32
	activeConfig func(unsafe.Pointer, **configDescriptor) int32
	freeConfig   func(*configDescriptor)
	claim        func(unsafe.Pointer, int32) int32
	release      func(unsafe.Pointer, int32) int32
	bulk         func(unsafe.Pointer, byte, unsafe.Pointer, int32, *int32, uint32) int32
	bus          func(unsafe.Pointer) byte
	address      func(unsafe.Pointer) byte
}
type Context struct {
	a      *api
	handle unsafe.Pointer
	unload func() error
}

func NewContext(library string) (*Context, error) {
	if library == "" {
		switch runtime.GOOS {
		case "windows":
			library = "libusb-1.0.dll"
		case "darwin":
			library = "libusb-1.0.dylib"
		default:
			library = "libusb-1.0.so.0"
		}
	}
	lookup, close, err := openLibrary(library)
	if err != nil {
		return nil, fmt.Errorf("load libusb-1.0 (%s): %w", library, err)
	}
	a := &api{}
	bindings := []struct {
		name string
		fn   any
	}{{"libusb_init", &a.init}, {"libusb_exit", &a.exit}, {"libusb_get_device_list", &a.list}, {"libusb_free_device_list", &a.freeList}, {"libusb_get_device_descriptor", &a.descriptor}, {"libusb_open", &a.open}, {"libusb_close", &a.close}, {"libusb_get_configuration", &a.getConfig}, {"libusb_set_configuration", &a.setConfig}, {"libusb_get_active_config_descriptor", &a.activeConfig}, {"libusb_free_config_descriptor", &a.freeConfig}, {"libusb_claim_interface", &a.claim}, {"libusb_release_interface", &a.release}, {"libusb_bulk_transfer", &a.bulk}, {"libusb_get_bus_number", &a.bus}, {"libusb_get_device_address", &a.address}}
	for _, b := range bindings {
		symbol, err := lookup(b.name)
		if err != nil {
			close()
			return nil, err
		}
		purego.RegisterFunc(b.fn, symbol)
	}
	c := &Context{a: a, unload: close}
	if code := a.init(&c.handle); code != 0 {
		close()
		return nil, fmt.Errorf("libusb_init: %d", code)
	}
	return c, nil
}
func (c *Context) Close() error {
	if c.handle == nil {
		return nil
	}
	c.a.exit(c.handle)
	c.handle = nil
	return c.unload()
}

type DeviceInfo struct {
	Bus, Address    byte
	Vendor, Product uint16
}

func (c *Context) devices(fn func(unsafe.Pointer, DeviceInfo) error) error {
	if c.handle == nil {
		return fmt.Errorf("USB context closed")
	}
	var list unsafe.Pointer
	count := c.a.list(c.handle, &list)
	if count < 0 {
		return fmt.Errorf("libusb enumeration: %d", count)
	}
	defer c.a.freeList(list, 1)
	if count > 65536 || count > 0 && list == nil {
		return fmt.Errorf("invalid libusb device-list count")
	}
	for _, device := range unsafe.Slice((*unsafe.Pointer)(list), int(count)) {
		var descriptor deviceDescriptor
		if code := c.a.descriptor(device, &descriptor); code != 0 {
			return fmt.Errorf("libusb descriptor: %d", code)
		}
		if descriptor.Vendor != 0xfca {
			continue
		}
		info := DeviceInfo{c.a.bus(device), c.a.address(device), descriptor.Vendor, descriptor.Product}
		if err := fn(device, info); err != nil {
			return err
		}
	}
	return nil
}
func (c *Context) Devices() ([]DeviceInfo, error) {
	var result []DeviceInfo
	err := c.devices(func(_ unsafe.Pointer, info DeviceInfo) error { result = append(result, info); return nil })
	return result, err
}

type Device struct {
	context   *Context
	handle    unsafe.Pointer
	Interface int32
	Info      DeviceInfo
	In, Out   byte
	buffer    []byte
}

func (c *Context) Open(products []uint16, bus, address int) (*Device, error) {
	eligible := func(info DeviceInfo) bool {
		if bus >= 0 && int(info.Bus) != bus || address >= 0 && int(info.Address) != address {
			return false
		}
		if len(products) == 0 {
			return true
		}
		for _, p := range products {
			if info.Product == p {
				return true
			}
		}
		return false
	}
	infos, err := c.Devices()
	if err != nil {
		return nil, err
	}
	matches := 0
	for _, info := range infos {
		if eligible(info) {
			matches++
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("expected one matching BlackBerry USB device, found %d", matches)
	}
	var result *Device
	err = c.devices(func(raw unsafe.Pointer, info DeviceInfo) error {
		if !eligible(info) {
			return nil
		}
		d := &Device{context: c, Interface: -1, Info: info}
		if code := c.a.open(raw, &d.handle); code != 0 {
			return fmt.Errorf("libusb_open: %d (check USB driver/access)", code)
		}
		ok := false
		defer func() {
			if !ok {
				d.Close()
			}
		}()
		var configuration int32
		if code := c.a.getConfig(d.handle, &configuration); code != 0 {
			return fmt.Errorf("libusb_get_configuration: %d", code)
		}
		if configuration != 1 {
			if code := c.a.setConfig(d.handle, 1); code != 0 {
				return fmt.Errorf("libusb_set_configuration: %d", code)
			}
		}
		var config *configDescriptor
		if code := c.a.activeConfig(raw, &config); code != 0 {
			return fmt.Errorf("libusb_get_active_config_descriptor: %d", code)
		}
		if config == nil {
			return fmt.Errorf("missing USB configuration")
		}
		defer c.a.freeConfig(config)
		if config.Interfaces == 0 || config.Interfaces > 32 || config.Interface == nil {
			return fmt.Errorf("invalid USB interfaces")
		}
		for _, iface := range unsafe.Slice(config.Interface, int(config.Interfaces)) {
			if iface.Count < 1 || iface.Count > 128 || iface.Alternate == nil {
				continue
			}
			for _, alt := range unsafe.Slice(iface.Alternate, int(iface.Count)) {
				d.In, d.Out = 0, 0
				if alt.Class != 0xff || alt.Alternate != 0 || alt.Endpoints == 0 || alt.Endpoints > 16 || alt.Endpoint == nil {
					continue
				}
				var inputs, outputs []byte
				for _, ep := range unsafe.Slice(alt.Endpoint, int(alt.Endpoints)) {
					if ep.Attributes&3 != 2 {
						continue
					}
					if ep.Address&0x80 != 0 {
						inputs = append(inputs, ep.Address)
					} else {
						outputs = append(outputs, ep.Address)
					}
				}
				expected := byte(1)
				if info.Product == 1 || info.Product == 0x8001 {
					expected = 2
				} else if info.Product == 0x8017 {
					expected = 7
				}
				for _, in := range inputs {
					for _, out := range outputs {
						if out == expected && in == expected|0x80 {
							d.In = in
							d.Out = out
						}
					}
				}
				if d.In == 0 && len(inputs) == 1 && len(outputs) == 1 {
					d.In = inputs[0]
					d.Out = outputs[0]
				}
				if d.In == 0 {
					continue
				}
				if code := c.a.claim(d.handle, int32(alt.Number)); code != 0 {
					return fmt.Errorf("libusb_claim_interface: %d", code)
				}
				d.Interface = int32(alt.Number)
				result = d
				ok = true
				return nil
			}
		}
		return fmt.Errorf("no vendor-specific USB bulk interface")
	})
	return result, err
}
func (d *Device) Close() error {
	if d.handle == nil {
		return nil
	}
	var err error
	if d.Interface >= 0 {
		if code := d.context.a.release(d.handle, d.Interface); code != 0 {
			err = fmt.Errorf("libusb_release_interface: %d", code)
		}
	}
	d.context.a.close(d.handle)
	d.handle = nil
	return err
}
func (d *Device) Send(b []byte) error {
	if d.handle == nil || len(b) == 0 || len(b) > 65535 {
		return fmt.Errorf("invalid USB write")
	}
	var transferred int32
	code := d.context.a.bulk(d.handle, d.Out, unsafe.Pointer(&b[0]), int32(len(b)), &transferred, 1500)
	runtime.KeepAlive(b)
	if code != 0 {
		return fmt.Errorf("USB write: %d", code)
	}
	if int(transferred) != len(b) {
		return fmt.Errorf("short USB write: %d/%d", transferred, len(b))
	}
	return nil
}
func (d *Device) Receive() ([]byte, error) {
	if d.handle == nil {
		return nil, fmt.Errorf("USB device closed")
	}
	for {
		if len(d.buffer) >= 4 {
			size := int(binary.LittleEndian.Uint16(d.buffer[2:]))
			if size < 4 {
				return nil, fmt.Errorf("invalid USB frame size")
			}
			if len(d.buffer) >= size {
				frame := append([]byte{}, d.buffer[:size]...)
				d.buffer = d.buffer[size:]
				return frame, nil
			}
		}
		if len(d.buffer) > 65535 {
			return nil, fmt.Errorf("USB frame buffer limit exceeded")
		}
		b := make([]byte, 65536)
		var transferred int32
		code := d.context.a.bulk(d.handle, d.In, unsafe.Pointer(&b[0]), int32(len(b)), &transferred, 1500)
		runtime.KeepAlive(b)
		if code != 0 {
			return nil, fmt.Errorf("USB read: %d", code)
		}
		if transferred <= 0 || int(transferred) > len(b) {
			return nil, errors.New("invalid USB transfer length")
		}
		d.buffer = append(d.buffer, b[:transferred]...)
	}
}
