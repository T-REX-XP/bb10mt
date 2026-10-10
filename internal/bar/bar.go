// Package bar handles unpacked BAR manifests using native BlackBerry encodings.
package bar

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
)

type Attribute struct{ Key, Value string }
type Section []Attribute
type Manifest []Section

func (s Section) Get(key string) string {
	for _, a := range s {
		if strings.EqualFold(a.Key, key) {
			return a.Value
		}
	}
	return ""
}
func (s *Section) Set(key, value string) {
	for i, a := range *s {
		if strings.EqualFold(a.Key, key) {
			(*s)[i].Value = value
			return
		}
	}
	*s = append(*s, Attribute{key, value})
}
func Parse(data []byte) (Manifest, error) {
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("manifest too large")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var result Manifest
	var section Section
	for _, line := range lines {
		if strings.ContainsAny(line, "\x00\r") {
			return nil, fmt.Errorf("invalid manifest control character")
		}
		if line == "" {
			if len(section) > 0 {
				result = append(result, section)
				section = nil
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			if len(section) == 0 {
				return nil, fmt.Errorf("orphan manifest continuation")
			}
			section[len(section)-1].Value += line[1:]
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key == "" || len(key) > 70 || strings.ContainsAny(key, "\x00\r\n: \t") || strings.ContainsAny(value, "\x00\r") {
			return nil, fmt.Errorf("invalid manifest attribute")
		}
		for _, a := range section {
			if strings.EqualFold(a.Key, key) {
				return nil, fmt.Errorf("duplicate manifest attribute %s", key)
			}
		}
		section = append(section, Attribute{key, value})
	}
	if len(section) > 0 {
		result = append(result, section)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}
	return result, nil
}
func (m Manifest) Bytes() []byte {
	var b strings.Builder
	for _, s := range m {
		for _, a := range s {
			line := a.Key + ": " + a.Value
			limit := 72
			for len(line) > limit {
				b.WriteString(line[:limit])
				b.WriteString("\r\n ")
				line = line[limit:]
				limit = 71
			}
			b.WriteString(line)
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
func digest(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
func local(root, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || !filepath.IsLocal(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe BAR asset path: %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean != name || strings.HasPrefix(strings.ToUpper(clean), "META-INF/") {
		return "", fmt.Errorf("invalid BAR asset path: %q", name)
	}
	full := filepath.Join(root, filepath.FromSlash(name))
	rel := root
	for _, p := range strings.Split(name, "/") {
		rel = filepath.Join(rel, p)
		st, err := os.Lstat(rel)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink BAR asset path")
		}
	}
	st, err := os.Stat(full)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("BAR asset is not regular")
	}
	return full, nil
}
func manifestFile(root string) (string, []byte, Manifest, error) {
	meta, err := os.Lstat(filepath.Join(root, "META-INF"))
	if err != nil {
		return "", nil, nil, err
	}
	if !meta.IsDir() || meta.Mode()&os.ModeSymlink != 0 {
		return "", nil, nil, fmt.Errorf("invalid META-INF directory")
	}
	path := filepath.Join(root, "META-INF", "MANIFEST.MF")
	st, err := os.Lstat(path)
	if err != nil {
		return "", nil, nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 16<<20 {
		return "", nil, nil, fmt.Errorf("invalid manifest file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, nil, err
	}
	m, err := Parse(b)
	return path, b, m, err
}

// Update hashes raw 64-byte SHA512 digests as unpadded base64url. The old
// implementation base64-encoded hexadecimal text and dropped native/ assets.
func Update(root string) error {
	path, before, m, err := manifestFile(root)
	if err != nil {
		return err
	}
	var result Manifest
	known := map[string]bool{}
	for _, s := range m {
		name := s.Get("Archive-Asset-Name")
		if name == "" {
			result = append(result, s)
			continue
		}
		if known[name] {
			return fmt.Errorf("duplicate BAR asset %s", name)
		}
		known[name] = true
		file, err := local(root, name)
		if err != nil {
			return err
		}
		hash, err := digest(file)
		if err != nil {
			return err
		}
		s.Set("Archive-Asset-SHA-512-Digest", hash)
		result = append(result, s)
	}
	var added []string
	err = filepath.WalkDir(root, func(file string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if name == "." {
			return nil
		}
		if strings.EqualFold(name, "META-INF") {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink BAR asset unsupported")
		}
		if d.IsDir() {
			return nil
		}
		if !known[name] {
			added = append(added, name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(added)
	for _, name := range added {
		file, err := local(root, name)
		if err != nil {
			return err
		}
		hash, err := digest(file)
		if err != nil {
			return err
		}
		result = append(result, Section{{"Archive-Asset-Name", name}, {"Archive-Asset-SHA-512-Digest", hash}})
	}
	return atomicfile.Replace(path, before, result.Bytes())
}
func Verify(root string) error {
	_, _, m, err := manifestFile(root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range m {
		name := s.Get("Archive-Asset-Name")
		if name == "" {
			continue
		}
		if seen[name] {
			return fmt.Errorf("duplicate BAR asset")
		}
		seen[name] = true
		file, err := local(root, name)
		if err != nil {
			return err
		}
		hash, err := digest(file)
		if err != nil {
			return err
		}
		if hash != s.Get("Archive-Asset-SHA-512-Digest") {
			return fmt.Errorf("BAR asset SHA512 mismatch: %s", name)
		}
	}
	if len(seen) == 0 {
		return fmt.Errorf("manifest contains no assets")
	}
	return filepath.WalkDir(root, func(file string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if strings.EqualFold(name, "META-INF") {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink BAR asset unsupported")
		}
		if d.IsDir() {
			return nil
		}
		if !seen[name] {
			return fmt.Errorf("BAR asset missing from manifest: %s", name)
		}
		return nil
	})
}
func id(prefix string) (string, error) {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	h := sha1.Sum(seed)
	return "andr" + prefix + base64.RawURLEncoding.EncodeToString(h[:]), nil
}

var idKeys = []string{"Package-Author-Id", "Package-Id", "Package-Version-Id", "Application-Id", "Application-Version-Id"}

func IDs(root string) error {
	path, before, m, err := manifestFile(root)
	if err != nil {
		return err
	}
	for i := range m {
		for j, key := range idKeys {
			if m[i].Get(key) != "" {
				value, err := id(string(rune('A' + j)))
				if err != nil {
					return err
				}
				m[i].Set(key, value)
			}
		}
	}
	return atomicfile.Replace(path, before, m.Bytes())
}
func Template(base, name string) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00\r\n") || name == "." || name == ".." {
		return fmt.Errorf("invalid BAR package name")
	}
	output := filepath.Join(base, "sys.data."+name)
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("package directory exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	dir, err := os.MkdirTemp(base, ".bb10mt-bar-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, p := range []string{"assets/data", "META-INF"} {
		if err = os.MkdirAll(filepath.Join(dir, p), 0755); err != nil {
			return err
		}
	}
	for _, p := range []string{"assets/links", "assets/perms"} {
		if err = os.WriteFile(filepath.Join(dir, p), nil, 0644); err != nil {
			return err
		}
	}
	a, err := id("A")
	if err != nil {
		return err
	}
	b, err := id("B")
	if err != nil {
		return err
	}
	c, err := id("C")
	if err != nil {
		return err
	}
	m := Manifest{Section{{"Archive-Manifest-Version", "1.5"}, {"Archive-Created-By", "BB10 MultiTool Go"}}, Section{{"Package-Type", "system-data"}, {"Package-Author", "Research In Motion Limited"}, {"Package-Author-Id", a}, {"Package-Name", "sys.data." + name}, {"Package-Id", b}, {"Package-Version", "1.0.0.0"}, {"Package-Version-Id", c}, {"Package-Architecture", "armle-v7"}}, Section{{"System-Data-Type", "os_data"}, {"System-Data-Requires-System", "os/10.0.0.8"}, {"System-Data-Persistence", "permanent"}}}
	if err = os.WriteFile(filepath.Join(dir, "META-INF", "MANIFEST.MF"), m.Bytes(), 0644); err != nil {
		return err
	}
	if err = Update(dir); err != nil {
		return err
	}
	return atomicfile.PublishDirectory(dir, output)
}
