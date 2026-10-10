// Package cli implements the portable command surface.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/autoloader"
	"github.com/bb10root/bb10mt/internal/bar"
	"github.com/bb10root/bb10mt/internal/batch"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/connect"
	"github.com/bb10root/bb10mt/internal/patchpkg"
	"github.com/bb10root/bb10mt/internal/qcfm"
	"github.com/bb10root/bb10mt/internal/qnx6"
	"github.com/bb10root/bb10mt/internal/raw"
	"github.com/bb10root/bb10mt/internal/rcfs"
	"github.com/bb10root/bb10mt/internal/vmdk"
)

const help = `BB10 MultiTool (Go migration)
Usage: bb10mt <command> [options]
  pack                 Pack QCFM V1/V2/hybrid partitions
  unpack               Extract a validated QCFM container
  verify               Verify QCFM structure and available CRCs
  split                Split a PE/CAP autoloader into containers
  autoloader create    Create an autoloader from a CAP executable
  autoloader extract   Extract the CAP executable
  autoloader verify    Validate a CAP offset table
  autoloader loaders   Extract embedded gzip RAM loaders
  batch                Build and verify OS/radio autoloaders from a patch script
  packages validate    Validate a local declarative package catalog
  plan                 Resolve packages and lock a compatible image build
  build                Build a new image/autoloader directory from a locked plan
  qnx6 mkfs/script     Create/edit a new QNX6 image
  qnx6 fsck/compact    Check or compact an image into a new copy
  qnx6 audit           Inspect all directory long-name checksums
  qnx6 repair-names    Repair long-name checksums into a new image
  qnx6 verify          Verify payload SHA256/mode/uid/gid from JSON manifest
  qnx6 read            Extract an image file by pathname
  qnx6 mount           Mount on Linux; optional new writable output
  bar                  template, update, ids, verify
  bar install          Install/register a BAR into a new QNX6 image
  rcfs                 read, verify, extract, modify, vmdk
  raw                  dump, nvram
  vmdk list            Inspect MBR/EBR/GPT partitions
  connect              Establish network development/SSH services
  usb list             List BlackBerry USB devices
  info/loader          Read device info or initialize its RAM loader
  flash/nuke           Flash validated firmware or request device wipe
  --version            Print build version
Existing Pascal commands are retained in the source reference during migration.
Use <command> --help for options. Existing outputs are never overwritten.
`

type flags struct {
	*flag.FlagSet
	input, list, output, container, cap, versions string
	sign, fast                                    bool
}

func newFlags(name string, errOut io.Writer) *flags {
	f := &flags{FlagSet: flag.NewFlagSet(name, flag.ContinueOnError)}
	f.SetOutput(errOut)
	return f
}
func (f *flags) str(p *string, short, long, value, usage string) {
	f.StringVar(p, long, value, usage)
	if short != "" {
		f.StringVar(p, short, value, usage)
	}
}
func (f *flags) boolean(p *bool, short, long string, usage string) {
	f.BoolVar(p, long, false, usage)
	if short != "" {
		f.BoolVar(p, short, false, usage)
	}
}
func (f *flags) inputs() {
	f.str(&f.input, "i", "input", "", "Comma-separated input files")
	f.str(&f.list, "l", "list", "", "Input list; relative paths resolve beside the list")
}
func (f *flags) parse(args []string) error {
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(f.Args(), " "))
	}
	return nil
}
func require(v, name string) error {
	if v == "" {
		return fmt.Errorf("--%s is required", name)
	}
	return nil
}
func inputRows(f *flags) ([]qcfm.Input, error) {
	if f.input != "" && f.list != "" {
		return nil, fmt.Errorf("use either --input or --list")
	}
	var rows []string
	base := "."
	if f.list != "" {
		b, e := os.ReadFile(f.list)
		if e != nil {
			return nil, e
		}
		rows = strings.Split(string(b), "\n")
		abs, e := filepath.Abs(f.list)
		if e != nil {
			return nil, e
		}
		base = filepath.Dir(abs)
	} else if f.input != "" {
		rows = strings.Split(f.input, ",")
	} else {
		return nil, fmt.Errorf("--input or --list is required")
	}
	result := []qcfm.Input{}
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row == "" {
			continue
		}
		in, e := qcfm.ParseInput(row, base)
		if e != nil {
			return nil, e
		}
		result = append(result, in)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("input list is empty")
	}
	return result, nil
}
func versionMask(s string) (int, error) {
	mask := 0
	for _, v := range strings.Split(s, ",") {
		n, e := strconv.Atoi(v)
		if e != nil || (n != 1 && n != 2) || mask&n != 0 {
			return 0, fmt.Errorf("versions must be 1, 2 or 1,2")
		}
		mask |= n
	}
	return mask, nil
}
func withReader(path string, fn func(binio.Reader) error) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("input must be a regular file")
	}
	return fn(binio.Reader{ReaderAt: f, Size: st.Size()})
}

// directory stages a whole extraction before exposing the output directory.
func directory(path string, fn func(string) error) error {
	if _, e := os.Lstat(path); e == nil {
		return fmt.Errorf("output already exists: %s", path)
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(path), ".bb10mt-extract-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = fn(tmp); e != nil {
		return e
	}
	return atomicfile.PublishDirectory(tmp, path)
}
func changeExt(path, ext string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + ext
}

func Run(args []string, out, errOut io.Writer, version string) error {
	if len(args) > 0 {
		switch args[0] {
		case "--complete":
			return complete(args[1:], out)
		case "--completion-file":
			_, err := io.WriteString(out, bashCompletion)
			return err
		case "--completion-file-pwsh":
			_, err := io.WriteString(out, pwshCompletion)
			return err
		case "--help-complete":
			if _, err := io.WriteString(out, help); err != nil {
				return err
			}
			for _, c := range commands {
				if err := Run(append(strings.Fields(c), "--help"), out, out, version); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, e := io.WriteString(out, help)
		return e
	}
	if args[0] == "--version" || args[0] == "-v" {
		_, e := fmt.Fprintln(out, "bb10mt", version)
		return e
	}
	name := args[0]
	args = args[1:]
	if name == "autoloader" || name == "qnx6" || name == "bar" || name == "raw" || name == "rcfs" || name == "vmdk" || name == "usb" || name == "packages" {
		if len(args) == 0 {
			return fmt.Errorf("%s subcommand required", name)
		}
		name += " " + args[0]
		args = args[1:]
	}
	if name == "packages validate" && len(args) == 1 && !strings.HasPrefix(args[0], "-") {
		args = []string{"--catalog", args[0]}
	}
	f := newFlags(name, errOut)
	var run func() error
	switch name {
	case "packages validate":
		catalog := f.String("catalog", "", "Local package catalog directory")
		run = func() error {
			if err := require(*catalog, "catalog"); err != nil {
				return err
			}
			c, err := patchpkg.Load(*catalog)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "Validated %d local packages\n", len(c.Packages))
			return err
		}
	case "plan":
		catalog := f.String("catalog", "", "Local package catalog directory")
		profile := f.String("profile", "", "JSON profile with exact package versions")
		f.str(&f.input, "i", "input", "", "QNX6 image or CAP autoloader")
		f.str(&f.output, "o", "output", "", "New plan JSON file")
		run = func() error {
			for name, value := range map[string]string{"input": f.input, "output": f.output, "catalog": *catalog, "profile": *profile} {
				if err := require(value, name); err != nil {
					return err
				}
			}
			p, err := patchpkg.NewPlan(f.input, *catalog, *profile)
			if err != nil {
				return err
			}
			if err = patchpkg.WritePlan(f.output, p); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "Locked %d packages, %d actions\n", len(p.Packages), len(p.Actions))
			return err
		}
	case "build":
		plan := f.String("plan", "", "Locked package plan JSON")
		f.str(&f.output, "o", "output", "", "New output directory")
		run = func() error {
			if err := require(*plan, "plan"); err != nil {
				return err
			}
			if err := require(f.output, "output"); err != nil {
				return err
			}
			return patchpkg.Build(*plan, f.output, out)
		}
	case "usb list", "flash", "info", "loader", "nuke":
		run = usbCommand(f, name, out)
	case "connect":
		var ip, password, keyFile, passwordEnv string
		f.str(&ip, "i", "ip", "", "Device IP/host (required; no interface guessing)")
		f.str(&password, "p", "password", "", "Explicit device password")
		f.str(&keyFile, "k", "sshPublicKey", "", "One ssh-rsa public key line")
		f.StringVar(&passwordEnv, "password-env", "", "Read password from this environment variable")
		port := f.Uint("port", 4455, "Network development-service port")
		timeout := f.Duration("timeout", 15*time.Second, "Per-step network timeout")
		run = func() error {
			if err := require(ip, "ip"); err != nil {
				return err
			}
			if err := require(keyFile, "sshPublicKey"); err != nil {
				return err
			}
			if passwordEnv != "" {
				if password != "" {
					return fmt.Errorf("use password or password-env")
				}
				var ok bool
				password, ok = os.LookupEnv(passwordEnv)
				if !ok {
					return fmt.Errorf("password environment variable is unset")
				}
			}
			if *port == 0 || *port > 65535 || *timeout <= 0 {
				return fmt.Errorf("invalid network port/timeout")
			}
			st, err := os.Stat(keyFile)
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() || st.Size() > 16384 {
				return fmt.Errorf("invalid public-key file")
			}
			b, err := os.ReadFile(keyFile)
			if err != nil {
				return err
			}
			key, err := connect.PublicKey(b)
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			dialer := net.Dialer{Timeout: *timeout}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(*port))))
			if err != nil {
				return err
			}
			err = connect.Run(ctx, conn, connect.Options{Password: password, PublicKey: key, Timeout: *timeout, Log: out})
			if err == context.Canceled {
				return nil
			}
			return err
		}
	case "rcfs vmdk":
		f.str(&f.input, "i", "image", "", "Source flat/monolithic-sparse disk image")
		f.str(&f.output, "o", "output", "", "New edited disk image")
		f.str(&f.list, "s", "script", "", "RCFS modification script")
		run = func() error {
			for k, v := range map[string]string{"image": f.input, "output": f.output, "script": f.list} {
				if err := require(v, k); err != nil {
					return err
				}
			}
			report, err := rcfs.ModifyDisk(f.input, f.output, f.list)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(report)
		}
	case "vmdk list":
		f.str(&f.input, "i", "image", "", "Flat/monolithic-sparse disk image")
		run = func() error {
			if err := require(f.input, "image"); err != nil {
				return err
			}
			return withReader(f.input, func(r binio.Reader) error {
				disk, err := vmdk.Open(r)
				if err != nil {
					return err
				}
				parts, err := disk.Partitions()
				if err != nil {
					return err
				}
				return json.NewEncoder(out).Encode(parts)
			})
		}
	case "rcfs modify":
		f.str(&f.input, "i", "image", "", "Source RCFS image")
		f.str(&f.output, "o", "output", "", "New edited RCFS image")
		f.str(&f.list, "s", "script", "", "push/chmod/corrupt script")
		var corrupt string
		f.str(&corrupt, "c", "corrupt", "", "Intentionally invalidate one stored payload and its VSIG checksum")
		run = func() error {
			if err := require(f.input, "image"); err != nil {
				return err
			}
			if err := require(f.output, "output"); err != nil {
				return err
			}
			report, err := rcfs.Modify(f.input, f.output, f.list, corrupt)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(report)
		}
	case "rcfs extract":
		f.str(&f.input, "i", "image", "", "RCFS image")
		f.str(&f.output, "o", "out", "", "New extraction directory")
		run = func() error {
			if err := require(f.input, "image"); err != nil {
				return err
			}
			if err := require(f.output, "out"); err != nil {
				return err
			}
			return withReader(f.input, func(r binio.Reader) error {
				im, err := rcfs.Open(r)
				if err != nil {
					return err
				}
				return directory(f.output, im.Extract)
			})
		}
	case "rcfs verify", "rcfs read":
		f.str(&f.input, "i", "image", "", "RCFS image")
		var path string
		if name == "rcfs read" {
			f.str(&path, "p", "path", "", "File pathname")
			f.str(&f.output, "o", "output", "", "New output file")
		}
		run = func() error {
			if err := require(f.input, "image"); err != nil {
				return err
			}
			return withReader(f.input, func(r binio.Reader) error {
				im, err := rcfs.Open(r)
				if err != nil {
					return err
				}
				if name == "rcfs verify" {
					report, err := im.Verify()
					if err != nil {
						return err
					}
					return json.NewEncoder(out).Encode(report)
				}
				if err = require(path, "path"); err != nil {
					return err
				}
				if err = require(f.output, "output"); err != nil {
					return err
				}
				n, err := im.Resolve(path)
				if err != nil {
					return err
				}
				return atomicfile.Write(f.output, func(f *os.File) error { return im.Data(n, f) })
			})
		}
	case "qnx6 compact":
		f.str(&f.input, "i", "image", "", "Source QNX6 image")
		f.str(&f.output, "o", "output", "", "New compacted image")
		run = func() error {
			if err := require(f.input, "image"); err != nil {
				return err
			}
			if err := require(f.output, "output"); err != nil {
				return err
			}
			report, err := qnx6.Compact(f.input, f.output)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(report)
		}
	case "autoloader loaders":
		f.str(&f.input, "i", "input", "", "Source CAP/autoloader executable")
		f.str(&f.output, "o", "output", "", "New base output directory")
		run = func() error {
			if err := require(f.input, "input"); err != nil {
				return err
			}
			output := changeExt(f.input, "")
			if f.output != "" {
				output = filepath.Join(f.output, output)
			}
			return withReader(f.input, func(r binio.Reader) error {
				loaders, err := autoloader.Loaders(r)
				if err != nil {
					return err
				}
				return directory(output, func(dir string) error {
					counts := map[uint32]int{}
					for _, loader := range loaders {
						name := fmt.Sprintf("loader_%08X-%02d.bin", loader.DeviceID, counts[loader.DeviceID])
						counts[loader.DeviceID]++
						if err := os.WriteFile(filepath.Join(dir, name), loader.Data, 0644); err != nil {
							return err
						}
					}
					return json.NewEncoder(out).Encode(loaders)
				})
			})
		}
	case "raw dump", "raw nvram":
		f.str(&f.input, "i", "input", "", "Raw input image")
		f.str(&f.output, "o", "output", "", "New output directory")
		var offset int64
		if name == "raw dump" {
			f.Int64Var(&offset, "mct", 0, "MCT byte offset (decimal or 0x...)")
			f.Int64Var(&offset, "m", 0, "MCT byte offset")
		}
		run = func() error {
			if err := require(f.input, "input"); err != nil {
				return err
			}
			if f.output == "" {
				f.output = changeExt(f.input, "_raw")
			}
			return withReader(f.input, func(r binio.Reader) error {
				var records []raw.Record
				if name == "raw nvram" {
					var err error
					records, err = raw.NVRE(r)
					if err != nil {
						return err
					}
				} else {
					parts, err := raw.MCT(r, offset)
					if err != nil {
						return err
					}
					counts := map[string]int{}
					for _, p := range parts {
						key := strings.ToLower(p.Name)
						counts[key]++
						suffix := ""
						if counts[key] > 1 {
							suffix = fmt.Sprintf("_%d", counts[key])
						}
						records = append(records, raw.Record{Name: fmt.Sprintf("%02x_%s%s.bin", p.ID, p.Name, suffix), Offset: p.Offset, Size: p.Size})
					}
				}
				return directory(f.output, func(dir string) error {
					for _, v := range records {
						if err := atomicfile.Write(filepath.Join(dir, v.Name), func(f *os.File) error {
							_, err := io.CopyN(f, io.NewSectionReader(r.ReaderAt, v.Offset, v.Size), v.Size)
							return err
						}); err != nil {
							return err
						}
					}
					return nil
				})
			})
		}
	case "bar install":
		var root string
		var opt bar.InstallOptions
		f.str(&root, "p", "path", "", "Unpacked BAR directory")
		f.str(&f.input, "i", "image", "", "Source QNX6 image")
		f.str(&f.output, "o", "output", "", "New image with the installed package")
		f.BoolVar(&opt.Replace, "replace", false, "Replace the same package, keeping its GID and private data")
		run = func() error {
			for k, v := range map[string]string{"path": root, "image": f.input, "output": f.output} {
				if e := require(v, k); e != nil {
					return e
				}
			}
			report, e := bar.InstallImage(root, f.input, f.output, opt)
			if e != nil {
				return e
			}
			return json.NewEncoder(out).Encode(report)
		}
	case "bar template", "bar update", "bar ids", "bar verify":
		f.str(&f.input, "p", "path", "", "Unpacked BAR directory (base directory for template)")
		var packageName string
		if name == "bar template" {
			f.str(&packageName, "n", "name", "", "Package name suffix")
		}
		run = func() error {
			if err := require(f.input, "path"); err != nil {
				return err
			}
			switch name {
			case "bar template":
				return bar.Template(f.input, packageName)
			case "bar update":
				return bar.Update(f.input)
			case "bar ids":
				return bar.IDs(f.input)
			default:
				return bar.Verify(f.input)
			}
		}
	case "batch":
		var batchOpt batch.Options
		f.BoolVar(&batchOpt.Compact, "compact", false, "Compact allocated filesystem blocks before packing")
		f.BoolVar(&batchOpt.Compact, "c", false, "Compact allocated filesystem blocks before packing")
		f.str(&f.input, "i", "input", "", "Source autoloader")
		f.str(&f.list, "s", "script", "", "Patch script")
		f.str(&f.output, "o", "output", "", "New output directory")
		run = func() error {
			for k, v := range map[string]string{"input": f.input, "script": f.list, "output": f.output} {
				if err := require(v, k); err != nil {
					return err
				}
			}
			return batch.BuildWithOptions(f.input, f.list, f.output, out, batchOpt)
		}
	case "qnx6 mkfs":
		f.str(&f.input, "i", "image", "", "New QNX6 image")
		blocks := f.Uint("blocks", 10240, "Total block count")
		inodes := f.Uint("inodes", 1024, "Inode count")
		bs := f.Uint("block-size", 4096, "Power-of-two block size")
		f.UintVar(blocks, "b", 10240, "Total blocks")
		f.UintVar(inodes, "n", 1024, "Inodes")
		f.UintVar(bs, "s", 4096, "Block size")
		run = func() error {
			if e := require(f.input, "image"); e != nil {
				return e
			}
			if *blocks > 0xffffffff || *inodes > 0xffffffff || *bs > 0xffffffff {
				return fmt.Errorf("geometry overflow")
			}
			return qnx6.Mkfs(f.input, uint32(*blocks), uint32(*inodes), uint32(*bs))
		}
	case "qnx6 script":
		var scriptOpt qnx6.ScriptOptions
		var blacklist string
		f.BoolVar(&scriptOpt.Debloat, "debloat", false, "Generate deferred-uninstall list inside the new image")
		f.StringVar(&blacklist, "blacklist", "", "Space-separated package IDs for --debloat (default legacy list)")
		f.str(&f.input, "i", "image", "", "Source QNX6 image")
		f.str(&f.list, "s", "script", "", "Patch script")
		f.str(&f.output, "o", "output", "", "New output image (required for safe mutation)")
		run = func() error {
			for k, v := range map[string]string{"image": f.input, "output": f.output} {
				if e := require(v, k); e != nil {
					return e
				}
			}
			if blacklist != "" {
				if !scriptOpt.Debloat {
					return fmt.Errorf("blacklist requires debloat")
				}
				scriptOpt.Blacklist = strings.Fields(blacklist)
			}
			return qnx6.ScriptWithOptions(f.input, f.list, f.output, out, scriptOpt)
		}
	case "qnx6 mount":
		var mountpoint string
		var opt qnx6.MountOptions
		f.str(&f.input, "i", "image", "", "Source QNX6 image")
		f.str(&mountpoint, "m", "mountpoint", "", "Existing empty Linux mount directory")
		f.str(&f.output, "o", "output", "", "New writable image, verified and published after unmount (default read-only)")
		f.BoolVar(&opt.Debug, "debug", false, "Enable FUSE diagnostic logging")
		run = func() error {
			if e := require(f.input, "image"); e != nil {
				return e
			}
			if e := require(mountpoint, "mountpoint"); e != nil {
				return e
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			return qnx6.Mount(ctx, f.input, f.output, mountpoint, opt, out)
		}
	case "qnx6 audit", "qnx6 repair-names", "qnx6 verify", "qnx6 read", "qnx6 fsck":
		f.str(&f.input, "i", "image", "", "QNX6 image")
		var path, manifest string
		var fix bool
		if name == "qnx6 fsck" {
			f.boolean(&fix, "f", "fix", "Repair supported checksums/counters into a new output image")
			f.str(&f.output, "o", "output", "", "New repaired image (required with --fix)")
		}
		if name == "qnx6 repair-names" || name == "qnx6 read" {
			f.str(&f.output, "o", "output", "", "New output image/file")
		}
		if name == "qnx6 read" {
			f.str(&path, "p", "path", "", "Image pathname")
		}
		if name == "qnx6 verify" {
			f.str(&manifest, "m", "manifest", "", "JSON array of path, sha256, optional mode, uid and gid")
		}
		run = func() error {
			if e := require(f.input, "image"); e != nil {
				return e
			}
			if name == "qnx6 fsck" && fix {
				if e := require(f.output, "output"); e != nil {
					return e
				}
				report, e := qnx6.Repair(f.input, f.output)
				if e != nil {
					return e
				}
				return json.NewEncoder(out).Encode(report)
			}
			if name == "qnx6 repair-names" {
				if e := require(f.output, "output"); e != nil {
					return e
				}
				a, e := qnx6.RepairNames(f.input, f.output)
				if e != nil {
					return e
				}
				return json.NewEncoder(out).Encode(a)
			}
			return withReader(f.input, func(r binio.Reader) error {
				im, e := qnx6.Open(r)
				if e != nil {
					return e
				}
				switch name {
				case "qnx6 fsck":
					report, e := im.Check()
					if e != nil {
						return e
					}
					if e = json.NewEncoder(out).Encode(report); e != nil {
						return e
					}
					if len(report.Errors) > 0 {
						return fmt.Errorf("filesystem check found %d errors", len(report.Errors))
					}
					_, e = fmt.Fprintln(out, "No errors found")
					return e
				case "qnx6 audit":
					a, e := im.AuditNames()
					if e != nil {
						return e
					}
					if e = json.NewEncoder(out).Encode(a); e != nil {
						return e
					}
					if len(a.Issues) > 0 {
						return fmt.Errorf("%d invalid long-name checksums", len(a.Issues))
					}
					return nil
				case "qnx6 verify":
					if e := require(manifest, "manifest"); e != nil {
						return e
					}
					b, e := os.ReadFile(manifest)
					if e != nil {
						return e
					}
					var expected []qnx6.Expected
					if e = json.Unmarshal(b, &expected); e != nil {
						return e
					}
					if len(expected) == 0 {
						return fmt.Errorf("payload manifest is empty")
					}
					return im.VerifyPayloads(expected)
				default:
					if e := require(path, "path"); e != nil {
						return e
					}
					if e := require(f.output, "output"); e != nil {
						return e
					}
					n, bad, e := im.Resolve(path)
					if e != nil {
						return e
					}
					if len(bad) > 0 {
						return fmt.Errorf("invalid pathname checksum")
					}
					if n.Mode()&0xf000 != 0x8000 {
						return fmt.Errorf("path is not a regular file")
					}
					return atomicfile.Write(f.output, func(out *os.File) error { return im.Data(n, out) })
				}
			})
		}
	case "pack":
		f.inputs()
		f.str(&f.container, "c", "container", "", "Target QCFM container")
		f.str(&f.versions, "", "versions", "2", "QCFM versions: 1, 2 or 1,2")
		f.boolean(&f.sign, "s", "sign", "Append legacy fake signature with CRC (not OEM signing)")
		f.boolean(&f.fast, "f", "fast", "Include erased blocks")
		run = func() error {
			if e := require(f.container, "container"); e != nil {
				return e
			}
			in, e := inputRows(f)
			if e != nil {
				return e
			}
			v, e := versionMask(f.versions)
			if e != nil {
				return e
			}
			return qcfm.Pack(f.container, in, qcfm.Options{Version: v, Fast: f.fast, Sign: f.sign})
		}
	case "verify", "unpack":
		f.str(&f.container, "c", "container", "", "QCFM container")
		if name == "unpack" {
			f.str(&f.output, "o", "output", "", "New output directory")
		}
		run = func() error {
			if e := require(f.container, "container"); e != nil {
				return e
			}
			return withReader(f.container, func(r binio.Reader) error {
				c, e := qcfm.Read(r)
				if e != nil {
					return e
				}
				if name == "verify" {
					return json.NewEncoder(out).Encode(c)
				}
				if f.output == "" {
					f.output = changeExt(f.container, "_unpacked")
				}
				return directory(f.output, func(dir string) error {
					rows := []string{}
					for i, ch := range c.Chunks() {
						ext := qcfm.Extension(ch.Type)
						if ext == ".unk" {
							ext = fmt.Sprintf(".unk_%d", i)
						}
						file := changeExt(f.container, fmt.Sprintf(".%d%s", i, ext))
						if e := atomicfile.Write(filepath.Join(dir, file), func(f *os.File) error { return qcfm.Extract(r, ch, c.Version == 1, f) }); e != nil {
							return e
						}
						if c.Version&1 != 0 {
							delta := uint32(0)
							if len(c.V1[i].Runs) > 0 {
								delta = c.V1[i].Runs[0].Offset
							}
							if len(c.V2) > 0 && len(c.V2[i].Runs) > 0 {
								delta -= c.V2[i].Runs[0].Offset
							}
							file += fmt.Sprintf("=%d,%d", delta, c.V1[i].Flags)
						}
						rows = append(rows, file)
					}
					return os.WriteFile(filepath.Join(dir, changeExt(f.container, ".lst")), []byte(strings.Join(rows, "\n")+"\n"), 0644)
				})
			})
		}
	case "autoloader create":
		f.inputs()
		f.str(&f.cap, "c", "cap", "cap.exe", "CAP executable")
		f.str(&f.output, "o", "output", "autoloader.exe", "Target autoloader")
		f.str(&f.versions, "", "versions", "2", "CAP tail version")
		run = func() error {
			in, e := inputRows(f)
			if e != nil {
				return e
			}
			paths := make([]string, len(in))
			for i, v := range in {
				if v.Delta != 0 || v.Flags != 0 {
					return fmt.Errorf("CAP inputs do not accept partition metadata")
				}
				paths[i] = v.Path
			}
			v, e := strconv.Atoi(f.versions)
			if e != nil {
				return e
			}
			return autoloader.Create(f.output, f.cap, paths, v)
		}
	case "autoloader extract":
		f.str(&f.input, "i", "input", "", "Input autoloader")
		f.str(&f.cap, "c", "cap", "cap.exe", "Output CAP executable")
		run = func() error {
			if e := require(f.input, "input"); e != nil {
				return e
			}
			return autoloader.ExtractCAP(f.input, f.cap)
		}
	case "split", "autoloader verify":
		f.str(&f.input, "i", "input", "", "Input autoloader")
		if name == "split" {
			f.str(&f.output, "o", "output", "", "New output directory")
		}
		run = func() error {
			if e := require(f.input, "input"); e != nil {
				return e
			}
			return withReader(f.input, func(r binio.Reader) error {
				h, e := autoloader.Read(r)
				if e != nil {
					return e
				}
				if name == "autoloader verify" {
					return json.NewEncoder(out).Encode(h)
				}
				if f.output == "" {
					f.output = changeExt(f.input, "_split")
				}
				return directory(f.output, func(dir string) error {
					for i, v := range h.Files {
						file := changeExt(f.input, fmt.Sprintf(".%d.signed", i))
						if e := atomicfile.Write(filepath.Join(dir, file), func(f *os.File) error {
							_, e := io.CopyN(f, io.NewSectionReader(r.ReaderAt, v.Offset, v.Size), v.Size)
							return e
						}); e != nil {
							return e
						}
					}
					return nil
				})
			})
		}
	default:
		return fmt.Errorf("command %q has not been migrated; see docs/MIGRATION.md", name)
	}
	if e := f.parse(args); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	return run()
}
