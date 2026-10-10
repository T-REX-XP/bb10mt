// Package patchpkg implements declarative, local firmware packages. It has no
// device access and no executable package hooks.
package patchpkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Requirement struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}
type Profile struct {
	SchemaVersion int           `json:"schemaVersion"`
	Packages      []Requirement `json:"packages"`
}
type Assertion struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Operation struct {
	Type           string   `json:"type"`
	Path           string   `json:"path"`
	Source         string   `json:"source"`
	SHA256         string   `json:"sha256"`
	Mode           string   `json:"mode"`
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	AllowAbsent    bool     `json:"allowAbsent"`
	OriginalSHA256 []string `json:"originalSha256,omitempty"`
}
type Manifest struct {
	SchemaVersion        int           `json:"schemaVersion"`
	ID                   string        `json:"id"`
	Version              string        `json:"version"`
	Kind                 string        `json:"kind"`
	App                  string        `json:"app,omitempty"`
	Requires             []Requirement `json:"requires,omitempty"`
	RequiresCapabilities []string      `json:"requiresCapabilities,omitempty"`
	Provides             []string      `json:"provides,omitempty"`
	Conflicts            []string      `json:"conflicts,omitempty"`
	Owns                 []string      `json:"owns,omitempty"`
	Assertions           []Assertion   `json:"assertions,omitempty"`
	Operations           []Operation   `json:"operations,omitempty"`
}
type Package struct {
	Manifest       Manifest
	Directory      string
	ManifestSHA256 string
}
type Catalog struct {
	Root     string
	Packages map[string]Package
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var appIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var fileChars = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
var modeChars = regexp.MustCompile(`^0?[0-7]{3}$`)
var capability = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}

// Reject duplicate keys as well as unknown fields: a lock must have one meaning.
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return fmt.Errorf("duplicate/invalid JSON key %v", k)
					}
					seen[key] = true
					if e = value(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := value(); e != nil {
						return e
					}
				}
			default:
				return fmt.Errorf("unexpected JSON delimiter")
			}
			_, err = d.Token()
		}
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func readJSON(p string, out any) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 4<<20 {
		return nil, fmt.Errorf("JSON exceeds 4 MiB")
	}
	return b, decode(b, out)
}
func cleanPath(p string, absolute bool) bool {
	if len(p) == 0 || len(p) > 1024 || !fileChars.MatchString(p) || strings.HasPrefix(p, "/") != absolute {
		return false
	}
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return path.Clean(p) == p
}
func validTarget(p string) bool {
	if strings.HasPrefix(p, "app:/") {
		p = strings.TrimPrefix(p, "app:")
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		return len(parts) > 1 && appIdentifier.MatchString(parts[0]) && cleanPath(p, true)
	}
	return cleanPath(p, true)
}

// regularPath bounds all host reads to a real package directory. Symlinks in
// any component are forbidden, including the package root itself.
func regularPath(root, rel string) (string, error) {
	if !cleanPath(rel, false) {
		return "", fmt.Errorf("unsafe payload path %q", rel)
	}
	p := root
	parts := append([]string{""}, strings.Split(rel, "/")...)
	for i, c := range parts {
		if c != "" {
			p = filepath.Join(p, c)
		}
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !st.IsDir()) || (i == len(parts)-1 && !st.Mode().IsRegular()) {
			return "", fmt.Errorf("payload is not a regular file beneath its package: %s", p)
		}
	}
	return p, nil
}
func fileHash(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func validateManifest(m Manifest) error {
	if m.SchemaVersion != 1 || !identifier.MatchString(m.ID) || !identifier.MatchString(m.Version) {
		return fmt.Errorf("invalid schema, package ID or exact version")
	}
	if m.Kind != "foundation" && m.Kind != "shared" && m.Kind != "app" {
		return fmt.Errorf("invalid package kind")
	}
	if m.Kind == "foundation" && (len(m.Operations) != 0 || len(m.Assertions) == 0 || len(m.Owns) != 0) {
		return fmt.Errorf("foundation must assert existing state without writes")
	}
	if m.Kind == "app" && (!appIdentifier.MatchString(m.App) || m.App == "sys.android") {
		return fmt.Errorf("invalid ordinary app namespace")
	}
	if m.Kind != "app" && m.App != "" {
		return fmt.Errorf("app is only valid for app packages")
	}
	for _, r := range m.Requires {
		if !identifier.MatchString(r.ID) || !identifier.MatchString(r.Version) {
			return fmt.Errorf("invalid exact dependency")
		}
	}
	for _, c := range append(append([]string{}, m.Provides...), m.RequiresCapabilities...) {
		if !capability.MatchString(c) {
			return fmt.Errorf("invalid capability")
		}
	}
	for _, c := range m.Conflicts {
		if !identifier.MatchString(c) {
			return fmt.Errorf("invalid conflict ID")
		}
	}
	owned := map[string]bool{}
	for _, p := range m.Owns {
		if !validTarget(p) || owned[p] {
			return fmt.Errorf("invalid or duplicate owned path %q", p)
		}
		owned[p] = true
	}
	used := map[string]bool{}
	for _, op := range m.Operations {
		if op.Type != "put-file" || !owned[op.Path] || used[op.Path] || !cleanPath(op.Source, false) || !validHash(op.SHA256) || !modeChars.MatchString(op.Mode) {
			return fmt.Errorf("invalid or unowned operation %q", op.Path)
		}
		used[op.Path] = true
		if !writable(m, op.Path) {
			return fmt.Errorf("protected or foreign destination %q", op.Path)
		}
		if !op.AllowAbsent && len(op.OriginalSHA256) == 0 {
			return fmt.Errorf("operation requires an original hash or allowAbsent: %s", op.Path)
		}
		for _, h := range op.OriginalSHA256 {
			if !validHash(h) {
				return fmt.Errorf("invalid original SHA256")
			}
		}
	}
	if len(used) != len(owned) {
		return fmt.Errorf("every owned file must have exactly one operation")
	}
	for _, a := range m.Assertions {
		if !validTarget(a.Path) || !validHash(a.SHA256) {
			return fmt.Errorf("invalid assertion")
		}
	}
	if len(m.Operations) > 4096 || len(m.Assertions) > 4096 {
		return fmt.Errorf("too many package actions")
	}
	return nil
}
func writable(m Manifest, p string) bool {
	if strings.HasPrefix(p, "app:/") {
		app := strings.Split(strings.TrimPrefix(p, "app:/"), "/")[0]
		return app != "sys.android" && (m.Kind == "shared" || (m.Kind == "app" && m.App == app))
	}
	// Root/system configuration is reserved for a future, explicit adapter.
	if !strings.HasPrefix(p, "/var/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".ssh" || part == "ssh" || part == "sshd" || part == "root" {
			return false
		}
	}
	return m.Kind == "app" || m.Kind == "shared"
}

func Load(root string) (*Catalog, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("catalog must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	c := &Catalog{Root: root, Packages: map[string]Package{}}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("catalog symlink forbidden: %s", entry.Name())
		}
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		mf, err := regularPath(dir, "manifest.json")
		if err != nil {
			return nil, err
		}
		var m Manifest
		b, err := readJSON(mf, &m)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", mf, err)
		}
		if err = validateManifest(m); err != nil {
			return nil, fmt.Errorf("%s: %w", mf, err)
		}
		if _, ok := c.Packages[m.ID]; ok {
			return nil, fmt.Errorf("duplicate package ID %s", m.ID)
		}
		for _, op := range m.Operations {
			p, e := regularPath(dir, op.Source)
			if e != nil {
				return nil, e
			}
			h, _, e := fileHash(p)
			if e != nil {
				return nil, e
			}
			if h != op.SHA256 {
				return nil, fmt.Errorf("payload SHA256 mismatch: %s", p)
			}
		}
		c.Packages[m.ID] = Package{m, entry.Name(), hashBytes(b)}
	}
	if len(c.Packages) == 0 {
		return nil, fmt.Errorf("empty package catalog")
	}
	// Validate dependency graphs even for packages not selected by a profile.
	available := map[string]bool{}
	for _, p := range c.Packages {
		for _, v := range p.Manifest.Provides {
			available[v] = true
		}
	}
	for _, p := range c.Packages {
		for _, v := range p.Manifest.RequiresCapabilities {
			if !available[v] {
				return nil, fmt.Errorf("catalog has no provider for %s", v)
			}
		}
	}
	for _, id := range sortedIDs(c.Packages) {
		if _, err = c.resolve(Profile{1, []Requirement{{id, c.Packages[id].Manifest.Version}}}, true); err != nil {
			return nil, err
		}
	}
	return c, nil
}
func sortedIDs(p map[string]Package) []string {
	ids := make([]string, 0, len(p))
	for id := range p {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (c *Catalog) resolve(profile Profile, validating bool) ([]Package, error) {
	if profile.SchemaVersion != 1 || len(profile.Packages) == 0 {
		return nil, fmt.Errorf("profile requires schemaVersion 1 and packages")
	}
	explicit := map[string]bool{}
	for _, r := range profile.Packages {
		if explicit[r.ID] {
			return nil, fmt.Errorf("duplicate profile package %s", r.ID)
		}
		explicit[r.ID] = true
	}
	state := map[string]int{}
	var result []Package
	var visit func(Requirement) error
	visit = func(r Requirement) error {
		p, ok := c.Packages[r.ID]
		if !ok || p.Manifest.Version != r.Version {
			return fmt.Errorf("missing exact package %s@%s", r.ID, r.Version)
		}
		if !validating && p.Manifest.Kind == "foundation" && !explicit[r.ID] {
			return fmt.Errorf("foundation %s must be explicitly selected", r.ID)
		}
		if state[r.ID] == 1 {
			return fmt.Errorf("dependency cycle at %s", r.ID)
		}
		if state[r.ID] == 2 {
			return nil
		}
		state[r.ID] = 1
		deps := append([]Requirement(nil), p.Manifest.Requires...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].ID < deps[j].ID })
		for _, dep := range deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[r.ID] = 2
		result = append(result, p)
		return nil
	}
	roots := append([]Requirement(nil), profile.Packages...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].ID < roots[j].ID })
	for _, r := range roots {
		if err := visit(r); err != nil {
			return nil, err
		}
	}
	providers := map[string]bool{}
	for _, p := range result {
		for _, v := range p.Manifest.Provides {
			providers[v] = true
		}
	}
	for _, p := range result {
		for _, id := range p.Manifest.Conflicts {
			if state[id] == 2 {
				return nil, fmt.Errorf("package conflict: %s / %s", p.Manifest.ID, id)
			}
		}
		if !validating {
			for _, v := range p.Manifest.RequiresCapabilities {
				if !providers[v] {
					return nil, fmt.Errorf("missing capability %s required by %s", v, p.Manifest.ID)
				}
			}
		}
	}
	return result, nil
}
