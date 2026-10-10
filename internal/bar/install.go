package bar

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bb10root/bb10mt/internal/qnx6"
)

type InstallOptions struct{ Replace bool }
type InstallReport struct {
	Package string `json:"package"`
	GID     uint32 `json:"gid"`
	Files   int    `json:"files"`
}
type installAsset struct {
	name, host, hash string
	size             int64
	mode             uint16
	dir              bool
}

func identifier(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func packageSection(m Manifest) (Section, error) {
	var pkg Section
	for _, s := range m {
		if s.Get("Package-Name") == "" {
			continue
		}
		for _, key := range []string{"Package-Name", "Package-Id", "Package-Version", "Package-Version-Id"} {
			if !identifier(s.Get(key)) {
				return nil, fmt.Errorf("invalid/missing BAR %s", key)
			}
		}
		if pkg != nil {
			return nil, fmt.Errorf("multiple package sections")
		}
		pkg = s
	}
	if pkg == nil {
		return nil, fmt.Errorf("package section missing")
	}
	if len(pkg.Get("Package-Name"))+1+len(pkg.Get("Package-Id")) > 510 {
		return nil, fmt.Errorf("package directory name exceeds QNX6 limit")
	}
	return pkg, nil
}

func prepareInstall(root string) (Manifest, Section, []byte, []installAsset, error) {
	if e := Verify(root); e != nil {
		return nil, nil, nil, nil, e
	}
	_, raw, m, e := manifestFile(root)
	if e != nil {
		return nil, nil, nil, nil, e
	}
	pkg, e := packageSection(m)
	if e != nil {
		return nil, nil, nil, nil, e
	}
	hashes := map[string]string{}
	for _, s := range m {
		if name := s.Get("Archive-Asset-Name"); name != "" {
			hashes[name] = s.Get("Archive-Asset-SHA-512-Digest")
		}
	}
	var assets []installAsset
	e = filepath.WalkDir(root, func(host string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(root, host)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if name == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("BAR installation rejects host symlinks")
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		a := installAsset{name: name, host: host, dir: d.IsDir(), size: st.Size(), mode: 0644}
		if d.IsDir() {
			a.mode = 0755
		} else {
			if !st.Mode().IsRegular() {
				return fmt.Errorf("BAR installation requires regular files")
			}
			f, e := os.Open(host)
			if e != nil {
				return e
			}
			var magic [4]byte
			f.Read(magic[:])
			f.Close()
			if string(magic[:]) == "\x7fELF" || string(magic[:2]) == "#!" || st.Mode().Perm()&0111 != 0 {
				a.mode = 0755
			}
			a.hash, e = digest(host)
			if e != nil {
				return e
			}
			if expected, ok := hashes[name]; ok && a.hash != expected {
				return fmt.Errorf("BAR changed during installation preflight: %s", name)
			}
		}
		assets = append(assets, a)
		return nil
	})
	return m, pkg, raw, assets, e
}

func installGID(ed *qnx6.Editor, pkg string, replace bool) (uint32, error) {
	used := map[uint32]bool{}
	var existing uint32
	for _, directory := range []string{"/var/etc/id", "/apps/gid2app"} {
		if e := ed.Mkdir(directory, true); e != nil {
			return 0, e
		}
		n, _, e := ed.Resolve(directory)
		if e != nil {
			return 0, e
		}
		entries, e := ed.Entries(n)
		if e != nil {
			return 0, e
		}
		for _, entry := range entries {
			gid, e := strconv.ParseUint(entry.Name, 10, 31)
			if e != nil || gid < 10000 {
				continue
			}
			used[uint32(gid)] = true
			if directory == "/apps/gid2app" {
				link, e := ed.Inode(entry.Inode)
				if e != nil {
					return 0, e
				}
				if link.Mode()&0xf000 == 0xa000 && link.Size() <= 4096 {
					var b bytes.Buffer
					if e = ed.Data(link, &b); e != nil {
						return 0, e
					}
					if b.String() == "/apps/"+pkg {
						if existing != 0 {
							return 0, fmt.Errorf("multiple GID mappings for package")
						}
						existing = uint32(gid)
					}
				}
			}
		}
	}
	apps, _, e := ed.Resolve("/apps")
	if e != nil {
		return 0, e
	}
	entries, e := ed.Entries(apps)
	if e != nil {
		return 0, e
	}
	for _, entry := range entries {
		n, e := ed.Inode(entry.Inode)
		if e != nil {
			return 0, e
		}
		if n.GID() >= 10000 {
			used[n.GID()] = true
		}
	}
	if _, _, e = ed.Resolve("/apps/" + pkg); e == nil {
		if !replace {
			return 0, fmt.Errorf("package exists; use --replace")
		}
		if existing == 0 {
			return 0, fmt.Errorf("existing package has no canonical GID mapping")
		}
		return existing, nil
	} else if !errors.Is(e, qnx6.ErrNotFound) {
		return 0, e
	}
	if existing != 0 {
		return 0, fmt.Errorf("orphaned package GID mapping")
	}
	for gid := uint32(10000); gid <= 2147483646; gid++ {
		if !used[gid] {
			return gid, nil
		}
	}
	return 0, fmt.Errorf("GID pool exhausted")
}

func registration(m Manifest, pkg Section, gid uint32) (map[string]string, error) {
	dname := pkg.Get("Package-Name") + "." + pkg.Get("Package-Id")
	var sections []any
	for _, s := range m {
		attrs := map[string]string{}
		for _, a := range s {
			attrs[a.Key] = a.Value
		}
		sections = append(sections, map[string]any{"_": attrs})
	}
	obj := map[string]any{"Package-Id": pkg.Get("Package-Id"), "Package-Version": pkg.Get("Package-Version"), "Package-Version-Id": pkg.Get("Package-Version-Id"), "_": map[string]any{"sections": sections}, "extras": "", "gid": gid}
	encoded, e := json.Marshal(obj)
	if e != nil {
		return nil, e
	}
	rows := map[string]string{"details": dname + ":json:" + string(encoded), "registered": fmt.Sprintf("%s::%s,%s,,,%d,", dname, pkg.Get("Package-Id"), pkg.Get("Package-Version"), gid)}
	display := pkg.Get("Display-Name")
	if display == "" {
		display = pkg.Get("Package-Name")
	}
	orientation := pkg.Get("Entry-Point-Orientation")
	if orientation == "" {
		orientation = "auto"
	}
	icons := pkg.Get("Entry-Point-Icon")
	if icons == "" {
		icons = "native/blackberry-tablet-default-icon.png"
	}
	entry := pkg.Get("Entry-Point")
	if entry == "" {
		entry = "app/native/" + pkg.Get("Package-Name")
	}
	for _, value := range []string{display, orientation, icons, entry, pkg.Get("Categories"), pkg.Get("Entry-Point-Splash-Screen")} {
		if strings.ContainsAny(value, "\r\n\x00,") {
			return nil, fmt.Errorf("unsupported control/comma in navigator CSV field")
		}
	}
	rows["navigator"] = fmt.Sprintf("%s::%s,%s,%s,%s,%s,,,,,1,%s,,,1", dname, strings.ReplaceAll(icons, ":", ","), display, pkg.Get("Categories"), strings.ReplaceAll(pkg.Get("Entry-Point-Splash-Screen"), ":", ","), orientation, entry)
	for _, s := range m {
		key, expr := s.Get("Entry-Point-Key"), s.Get("Entry-Point")
		if key == "" || !strings.Contains(expr, "[") {
			continue
		}
		if !identifier(key) {
			return nil, fmt.Errorf("invalid service entry point")
		}
		_, params, _ := strings.Cut(expr, "[")
		params, _, ok := strings.Cut(params, "]")
		if !ok {
			return nil, fmt.Errorf("invalid service options")
		}
		timeout := uint64(30)
		paths := []string{}
		for _, field := range strings.Fields(params) {
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("invalid service parameter")
			}
			switch k {
			case "timeout":
				timeout, e = strconv.ParseUint(v, 10, 32)
				if e != nil || timeout == 0 || timeout > 3600 {
					return nil, fmt.Errorf("invalid service timeout")
				}
			case "path":
				for _, p := range strings.Split(v, ":") {
					if strings.ContainsAny(p, "\r\n\x00") || p == "" {
						return nil, fmt.Errorf("invalid service path")
					}
					paths = append(paths, p)
				}
			default:
				return nil, fmt.Errorf("unsupported service parameter %s", k)
			}
		}
		data, e := json.Marshal(map[string]any{"entry": key, "timeout": timeout, "path": paths})
		if e != nil {
			return nil, e
		}
		rowKey := dname + ".." + key
		rows[rowKey] = rowKey + "..json:" + string(data)
	}
	return rows, nil
}

// ppsRow replaces exact object keys across numbered files, removing duplicate
// registrations while preserving unrelated packages and object headers.
func ppsRow(ed *qnx6.Editor, directory, base, key, row string) error {
	return ppsEdit(ed, directory, base, func(line string) bool {
		return strings.HasPrefix(line, key+":") || strings.HasPrefix(line, key+"..json:")
	}, row)
}

func ppsEdit(ed *qnx6.Editor, directory, base string, match func(string) bool, row string) error {
	if e := ed.Mkdir(directory, true); e != nil {
		return e
	}
	n, _, e := ed.Resolve(directory)
	if e != nil {
		return e
	}
	entries, e := ed.Entries(n)
	if e != nil {
		return e
	}
	var files []string
	for _, entry := range entries {
		if entry.Name == base {
			files = append(files, path.Join(directory, entry.Name))
			continue
		}
		if strings.HasPrefix(entry.Name, base+".") {
			suffix := strings.TrimPrefix(entry.Name, base+".")
			if _, e = strconv.ParseUint(suffix, 10, 32); e == nil {
				files = append(files, path.Join(directory, entry.Name))
			}
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		files = []string{path.Join(directory, base)}
	}
	found := false
	for i, file := range files {
		data, e := ed.ReadFile(file, 64<<20)
		if errors.Is(e, qnx6.ErrNotFound) {
			data = []byte("@" + base + "\n")
		} else if e != nil {
			return e
		}
		var kept []string
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			trimmed := strings.TrimSpace(line)
			if match(trimmed) {
				if !found && row != "" {
					kept = append(kept, row)
					found = true
				}
				continue
			}
			if line != "" {
				kept = append(kept, line)
			}
		}
		if !found && row != "" && i == len(files)-1 {
			kept = append(kept, row)
			found = true
		}
		result := []byte(strings.Join(kept, "\n") + "\n")
		if e = ed.WriteFile(file, bytes.NewReader(result), uint64(len(result)), false); e != nil {
			return e
		}
	}
	return nil
}

// InstallImage installs and registers an unpacked BAR in a new QNX6 image. The
// source image, other applications and their private-data ownership are kept.
func InstallImage(root, input, output string, opt InstallOptions) (InstallReport, error) {
	var report InstallReport
	m, pkg, manifest, assets, e := prepareInstall(root)
	if e != nil {
		return report, e
	}
	dname := pkg.Get("Package-Name") + "." + pkg.Get("Package-Id")
	report.Package = dname
	e = qnx6.Transaction(input, output, func(ed *qnx6.Editor) error {
		gid, e := installGID(ed, dname, opt.Replace)
		if e != nil {
			return e
		}
		report.GID = gid
		rows, e := registration(m, pkg, gid)
		if e != nil {
			return e
		}
		target := "/apps/" + dname
		oldServices := map[string]bool{}
		if _, _, e = ed.Resolve(target); e == nil {
			oldRaw, e := ed.ReadFile(target+"/META-INF/MANIFEST.MF", 16<<20)
			if e != nil {
				return e
			}
			oldManifest, e := Parse(oldRaw)
			if e != nil {
				return e
			}
			for _, section := range oldManifest {
				if key := section.Get("Entry-Point-Key"); key != "" {
					oldServices[dname+".."+key+"..json"] = true
				}
			}
			if e = ed.Remove(target, true); e != nil {
				return e
			}
		} else if !errors.Is(e, qnx6.ErrNotFound) {
			return e
		}
		if e = ed.Mkdir(target, true); e != nil {
			return e
		}
		if e = ed.SetAttributes(target, 0755, 89, gid); e != nil {
			return e
		}
		var expected []qnx6.Expected
		for _, a := range assets {
			dst := path.Join(target, a.name)
			if a.dir {
				if e = ed.Mkdir(dst, true); e != nil {
					return e
				}
			} else {
				f, e := os.Open(a.host)
				if e != nil {
					return e
				}
				h512, h256 := sha512.New(), sha256.New()
				e = ed.WriteFile(dst, io.TeeReader(f, io.MultiWriter(h512, h256)), uint64(a.size), true)
				ce := f.Close()
				if e != nil {
					return e
				}
				if ce != nil {
					return ce
				}
				if base64.RawURLEncoding.EncodeToString(h512.Sum(nil)) != a.hash {
					return fmt.Errorf("BAR source changed: %s", a.name)
				}
				mode, uid := a.mode, uint32(89)
				expected = append(expected, qnx6.Expected{Path: dst, SHA256: fmt.Sprintf("%x", h256.Sum(nil)), Mode: &mode, UID: &uid, GID: &gid})
				report.Files++
			}
			if e = ed.SetAttributes(dst, a.mode, 89, gid); e != nil {
				return e
			}
		}
		idPath := fmt.Sprintf("/var/etc/id/%d", gid)
		if _, _, e = ed.Resolve(idPath); errors.Is(e, qnx6.ErrNotFound) {
			if e = ed.WriteFile(idPath, bytes.NewReader(nil), 0, true); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		link := fmt.Sprintf("/apps/gid2app/%d", gid)
		if _, _, e = ed.Resolve(link); errors.Is(e, qnx6.ErrNotFound) {
			if e = ed.Symlink(target, link); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		dataRoot := "/accounts/1000/_startup_data/appdata/" + dname
		for _, name := range []string{"", "data", "logs", "sharewith", "tmp"} {
			p := path.Join(dataRoot, name)
			if e = ed.Mkdir(p, true); e != nil {
				return e
			}
			if e = ed.SetAttributes(p, 0755, 1000, gid); e != nil {
				return e
			}
		}
		for _, item := range []struct{ directory, base, key, row string }{
			{"/var/pps/system/installer/appdetails", "applications", dname, rows["details"]},
			{"/var/pps/system/installer/registeredapps", "applications", dname, rows["registered"]},
			{"/var/pps/system/navigator/applications", "applications", dname, rows["navigator"]},
		} {
			if e = ppsRow(ed, item.directory, item.base, item.key, item.row); e != nil {
				return e
			}
		}
		var services []string
		if e = ppsEdit(ed, "/var/pps/system", "bslauncher", func(line string) bool {
			key, _, _ := strings.Cut(line, ":")
			return oldServices[key]
		}, ""); e != nil {
			return e
		}
		for key := range rows {
			if strings.HasPrefix(key, dname+"..") {
				services = append(services, key)
			}
		}
		sort.Strings(services)
		for _, key := range services {
			if e = ppsRow(ed, "/var/pps/system", "bslauncher", key, rows[key]); e != nil {
				return e
			}
		}
		_, current, _, e := manifestFile(root)
		if e != nil {
			return e
		}
		if !bytes.Equal(manifest, current) {
			return fmt.Errorf("BAR manifest changed during installation")
		}
		return ed.VerifyPayloads(expected)
	})
	return report, e
}
