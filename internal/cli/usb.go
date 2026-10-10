package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/bb10root/bb10mt/internal/runtimeenv"
	"github.com/bb10root/bb10mt/internal/usb"
)

func usbCommand(f *flags, name string, out io.Writer) func() error {
	var library, passwordEnv string
	o := usb.Options{Bus: -1, Address: -1, Wait: 30 * time.Second, RunDelay: time.Second}
	f.StringVar(&library, "libusb", "", "Override the bundled libusb-1.0 shared library")
	f.IntVar(&o.Bus, "bus", -1, "Select USB bus (-1 selects any)")
	f.IntVar(&o.Address, "address", -1, "Select initial USB address (-1 selects any)")
	if name == "usb list" {
		return func() (err error) {
			c, e := usb.NewContext(library)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, c.Close()) }()
			devices, e := c.Devices()
			if e != nil {
				return e
			}
			return json.NewEncoder(out).Encode(devices)
		}
	}
	f.StringVar(&o.LoaderDirectory, "loaders", "", "Loader directory (default: loaders beside the executable)")
	f.StringVar(&o.LoaderFile, "loader-file", "", "Explicit RAM loader file; validated against detected model")
	f.StringVar(&o.Config, "config", "", "Existing bb10mt.ini [Loaders] mapping to files in --loaders")
	f.StringVar(&o.LoaderArchive, "loader-archive", "", "Legacy loaders.dat archive (uses --config mapping)")
	f.StringVar(&o.Password, "password", "", "Explicit device password (one attempt, no retry)")
	f.StringVar(&passwordEnv, "password-env", "", "Read device password from this environment variable")
	f.DurationVar(&o.Wait, "timeout", 30*time.Second, "Maximum wait for USB boot/loader enumeration")
	f.DurationVar(&o.RunDelay, "runloader", time.Second, "Delay after executing RAM loader")
	rebootBoot := f.Bool("reboot-to-bootrom", false, "Request a normal-mode reboot before waiting for BootROM")
	bootOnly := false
	reboot := false
	probeAll := false
	if name == "loader" {
		f.BoolVar(&probeAll, "probe-all", false, "Probe up to 256 loader candidates once; reboot each success; emit JSON lines")
	}
	if name == "info" {
		f.BoolVar(&bootOnly, "bootrom-only", false, "Read BootROM metadata without starting a RAM loader")
	}
	if name == "flash" || name == "loader" {
		f.BoolVar(&reboot, "reboot", false, "Reboot after successful operation")
	}
	if name == "flash" {
		f.inputs()
		f.str(&f.versions, "v", "version", "2", "Raw partition QCFM version: 1, 2 or 1,2")
	}
	return func() (err error) {
		executable, e := runtimeenv.Program()
		if e != nil {
			return e
		}
		if o.LoaderDirectory == "" {
			o.LoaderDirectory = filepath.Join(filepath.Dir(executable), "loaders")
		}
		if probeAll && (o.LoaderFile != "" || reboot) {
			return fmt.Errorf("probe-all already reboots each success; do not combine with loader-file or reboot")
		}
		for _, item := range []struct {
			value *string
			name  string
		}{{&o.Config, "bb10mt.ini"}, {&o.LoaderArchive, "loaders.dat"}} {
			if *item.value == "" {
				path := filepath.Join(filepath.Dir(executable), item.name)
				if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() {
					*item.value = path
				}
			}
		}
		if o.Config == "" && runtimeenv.Root() != "" {
			o.Config = filepath.Join(runtimeenv.Root(), "bb10mt.ini")
		}
		if o.Bus < -1 || o.Bus > 255 || o.Address < -1 || o.Address > 255 || o.Wait <= 0 || o.RunDelay < 0 {
			return fmt.Errorf("invalid USB selector/timeout/delay")
		}
		if passwordEnv != "" {
			if o.Password != "" {
				return fmt.Errorf("use password or password-env")
			}
			var ok bool
			o.Password, ok = os.LookupEnv(passwordEnv)
			if !ok {
				return fmt.Errorf("password environment variable is unset")
			}
		}
		var prepared []usb.Prepared
		if name == "flash" {
			inputs, e := inputRows(f)
			if e != nil {
				return e
			}
			version, e := versionMask(f.versions)
			if e != nil {
				return e
			}
			stage, e := os.MkdirTemp("", "bb10mt-flash-*")
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
			prepared, e = usb.PrepareFirmware(stage, inputs, version)
			if e != nil {
				return e
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		c, e := usb.NewContext(library)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, c.Close()) }()
		if *rebootBoot {
			if e = usb.RebootToBootROM(c, o); e != nil {
				return e
			}
		}
		if probeAll {
			return usb.ProbeLoaders(ctx, c, o, func(r usb.ProbeResult) error { return json.NewEncoder(out).Encode(r) })
		}
		s, e := usb.OpenBoot(ctx, c, o)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, s.Close()) }()
		if name == "info" && bootOnly {
			return json.NewEncoder(out).Encode(s.Info)
		}
		if name == "nuke" {
			if e = s.PrepareBoot(ctx, o.Password); e != nil {
				return e
			}
			if e = s.P.Nuke(); e != nil {
				return e
			}
			_, e = fmt.Fprintln(out, "Device acknowledged nuke request.")
			return e
		}
		if e = s.StartLoader(ctx, c, o); e != nil {
			return e
		}
		switch name {
		case "info":
			info, e := s.ReadInfo()
			if e != nil {
				return e
			}
			return json.NewEncoder(out).Encode(info)
		case "flash":
			for _, input := range prepared {
				report, e := s.P.Flash(ctx, s.Info.ModelID, input)
				if e != nil {
					return e
				}
				if e = json.NewEncoder(out).Encode(report); e != nil {
					return e
				}
			}
		case "loader":
			if e = json.NewEncoder(out).Encode(map[string]any{"boot": s.Info, "loader": s.Loader, "status": "RAM loader initialized"}); e != nil {
				return e
			}
		}
		if reboot {
			return s.Reboot()
		}
		return nil
	}
}
