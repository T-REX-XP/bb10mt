package usb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/loaderarchive"
)

const MaxLoaderSize = 32 << 20

func LoaderAddress(model uint32) (uint32, error) {
	if model == 0xb600240a {
		return 0x0dd00000, nil
	}
	switch model & 0xffff {
	case 0x080a, 0x240a, 0x270a, 0x2a0a, 0x2e0a, 0x2e07:
		return 0x80200000, nil
	case 0x1a06, 0x2307, 0x2607, 0x260a:
		return 0x80100000, nil
	case 0x2c0a:
		return 0x0dd00000, nil
	}
	return 0, fmt.Errorf("unsupported model RAM address: %08X", model)
}

// ValidateLoader checks the legacy structural markers, populated signature and
// model address. It does not authenticate the OEM signature.
func ValidateLoader(data []byte, model uint32) (uint32, error) {
	address, err := LoaderAddress(model)
	if err != nil {
		return 0, err
	}
	if len(data) < 10240 || len(data) > MaxLoaderSize || binary.LittleEndian.Uint32(data[4:]) != 0xd7d32d1f || binary.LittleEndian.Uint32(data[len(data)-8:]) != 0xd7c82d1f {
		return 0, fmt.Errorf("invalid RAM loader markers/size")
	}
	if binary.LittleEndian.Uint32(data[8:]) != address {
		return 0, fmt.Errorf("RAM loader address does not match model %08X", model)
	}
	if bytes.Equal(data[len(data)-144:len(data)-16], bytes.Repeat([]byte{0xff}, 128)) {
		return 0, fmt.Errorf("RAM loader has an erased signature")
	}
	return address, nil
}

// LoaderMap reads the existing [Loaders] INI section without accepting paths
// outside the loader directory. Duplicate IDs are rejected rather than hidden.
func LoaderMap(r io.Reader) (map[uint32]string, error) {
	s := bufio.NewScanner(io.LimitReader(r, 1<<20+1))
	s.Buffer(make([]byte, 4096), 65536)
	result := map[uint32]string{}
	section := ""
	total := 0
	for s.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\ufeff"))
		total += len(s.Bytes()) + 1
		if total > 1<<20 {
			return nil, fmt.Errorf("loader INI exceeds 1 MiB")
		}
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		if section != "loaders" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		id, e := strconv.ParseUint(key, 16, 32)
		if !ok || len(key) != 8 || e != nil || value == "" || strings.ContainsAny(value, "/\\:\x00") || value == "." || value == ".." {
			return nil, fmt.Errorf("invalid loader INI row")
		}
		if _, ok := result[uint32(id)]; ok {
			return nil, fmt.Errorf("duplicate loader model %08X", id)
		}
		result[uint32(id)] = value
	}
	return result, s.Err()
}

func readLoader(path string, model uint32) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() < 10240 || st.Size() > MaxLoaderSize {
		return nil, fmt.Errorf("invalid RAM loader file size")
	}
	data, e := io.ReadAll(io.LimitReader(f, MaxLoaderSize+1))
	if e != nil {
		return nil, e
	}
	_, e = ValidateLoader(data, model)
	return data, e
}

func SelectLoader(dir, explicit, config string, model uint32) ([]byte, string, error) {
	return SelectLoaderWithArchive(dir, explicit, config, "", model)
}
func SelectLoaderWithArchive(dir, explicit, config, archive string, model uint32) ([]byte, string, error) {
	if explicit != "" {
		b, e := readLoader(explicit, model)
		return b, explicit, e
	}
	if dir == "" {
		dir = "loaders"
	}
	entries, e := os.ReadDir(dir)
	if e != nil && !(os.IsNotExist(e) && archive != "") {
		return nil, "", e
	}
	prefix := fmt.Sprintf("LOADER_%08X", model)
	var candidates []string
	for _, entry := range entries {
		name := strings.ToUpper(entry.Name())
		if !entry.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".BIN") {
			candidates = append(candidates, filepath.Join(dir, entry.Name()))
		}
	}
	resource := ""
	if config != "" {
		f, e := os.Open(config)
		if e != nil {
			return nil, "", e
		}
		mapping, e := LoaderMap(f)
		ce := f.Close()
		if e != nil {
			return nil, "", e
		}
		if ce != nil {
			return nil, "", ce
		}
		if name, ok := mapping[model]; ok {
			resource = name
			candidates = append(candidates, filepath.Join(dir, name), filepath.Join(dir, name+".bin"))
		}
	}
	sort.Strings(candidates)
	var failures []string
	for _, name := range candidates {
		data, e := readLoader(name, model)
		if e == nil {
			return data, name, nil
		}
		failures = append(failures, filepath.Base(name)+": "+e.Error())
	}
	if archive != "" && resource != "" {
		f, e := os.Open(archive)
		if e != nil {
			return nil, "", e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return nil, "", e
		}
		a, e := loaderarchive.Read(binio.Reader{ReaderAt: f, Size: st.Size()})
		if e != nil {
			return nil, "", e
		}
		data, e := a.Extract(resource)
		if e != nil {
			return nil, "", e
		}
		if _, e = ValidateLoader(data, model); e != nil {
			return nil, "", e
		}
		return data, archive + ":" + resource, nil
	}
	return nil, "", fmt.Errorf("no valid loader for %08X in %s: %s", model, dir, strings.Join(failures, "; "))
}
