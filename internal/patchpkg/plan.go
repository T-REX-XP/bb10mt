package patchpkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/bar"
	"github.com/bb10root/bb10mt/internal/batch"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

type Input struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Format string `json:"format"`
}
type PackageLock struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	Directory      string `json:"directory"`
	ManifestSHA256 string `json:"manifestSha256"`
}
type State struct {
	Absent bool   `json:"absent,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Size   uint64 `json:"size,omitempty"`
	Mode   uint16 `json:"mode,omitempty"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}
type Action struct {
	Package         string     `json:"package"`
	Path            string     `json:"path"`
	Before          State      `json:"before"`
	Operation       *Operation `json:"operation,omitempty"`
	AssertionSHA256 string     `json:"assertionSha256,omitempty"`
}
type Plan struct {
	SchemaVersion int           `json:"schemaVersion"`
	Input         Input         `json:"input"`
	Catalog       string        `json:"catalog"`
	Profile       Profile       `json:"profile"`
	Packages      []PackageLock `json:"packages"`
	Actions       []Action      `json:"actions"`
}

func openImage(input string, visit func(*qnx6.Image, string) error) error {
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	im, rawErr := qnx6.Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if rawErr == nil {
		defer f.Close()
		return visit(im, "qnx6")
	}
	f.Close()
	tmp, err := os.MkdirTemp("", "bb10mt-plan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(tmp, "source.ufs")
	if err = batch.ExtractFilesystem(input, p); err != nil {
		return fmt.Errorf("input is neither supported QNX6 nor CAP: %w", err)
	}
	f, err = os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil {
		return err
	}
	im, err = qnx6.Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		return err
	}
	return visit(im, "cap")
}
func resolveTarget(im *qnx6.Image, target string) (string, error) {
	if !strings.HasPrefix(target, "app:/") {
		return target, nil
	}
	app, suffix, _ := strings.Cut(strings.TrimPrefix(target, "app:/"), "/")
	dir, _, err := im.Resolve("/apps")
	if err != nil {
		return "", err
	}
	entries, err := im.Entries(dir)
	if err != nil {
		return "", err
	}
	var found string
	for _, entry := range entries {
		if entry.Name == app || strings.HasPrefix(entry.Name, app+".") {
			if !cleanPath(entry.Name, false) {
				return "", fmt.Errorf("unsafe installed app name")
			}
			n, err := im.Inode(entry.Inode)
			if err != nil {
				return "", err
			}
			if n.Mode()&0xf000 != 0x4000 {
				return "", fmt.Errorf("app is not a directory: %s", entry.Name)
			}
			matches, err := appIdentity(im, entry.Name, app)
			if err != nil {
				return "", err
			}
			if !matches {
				continue
			}
			if found != "" {
				return "", fmt.Errorf("ambiguous installed app %s: %s / %s", app, found, entry.Name)
			}
			found = entry.Name
		}
	}
	if found == "" {
		return "", fmt.Errorf("required installed app missing: %s", app)
	}
	return "/apps/" + found + "/" + suffix, nil
}

func appIdentity(im *qnx6.Image, directory, app string) (bool, error) {
	n, _, err := im.Resolve("/apps/" + directory + "/META-INF/MANIFEST.MF")
	if errors.Is(err, qnx6.ErrNotFound) {
		return true, nil
	} // Legacy overlays can omit BAR metadata.
	if err != nil {
		return false, err
	}
	if n.Mode()&0xf000 != 0x8000 || n.Size() > 16<<20 {
		return false, fmt.Errorf("invalid installed BAR manifest: %s", directory)
	}
	var data strings.Builder
	if err = im.Data(n, &data); err != nil {
		return false, err
	}
	m, err := bar.Parse([]byte(data.String()))
	if err != nil {
		return false, fmt.Errorf("installed BAR manifest %s: %w", directory, err)
	}
	name, id := "", ""
	for _, section := range m {
		if v := section.Get("Package-Name"); v != "" {
			if name != "" {
				return false, fmt.Errorf("ambiguous BAR package identity: %s", directory)
			}
			name, id = v, section.Get("Package-Id")
		}
	}
	if name == "" || id == "" || name+"."+id != directory {
		return false, fmt.Errorf("BAR package identity differs from directory: %s", directory)
	}
	return name == app, nil
}
func inspect(im *qnx6.Image, p string) (State, error) {
	// Missing parents are permissible. Existing parents must be real directories,
	// never symlinks or other inode types; Resolve deliberately does not follow them.
	parts := strings.Split(strings.TrimPrefix(path.Dir(p), "/"), "/")
	parent := ""
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		parent += "/" + part
		n, _, err := im.Resolve(parent)
		if errors.Is(err, qnx6.ErrNotFound) {
			return State{Absent: true}, nil
		}
		if err != nil {
			return State{}, err
		}
		if n.Mode()&0xf000 != 0x4000 {
			return State{}, fmt.Errorf("non-directory image parent %s", parent)
		}
	}
	n, _, err := im.Resolve(p)
	if errors.Is(err, qnx6.ErrNotFound) {
		return State{Absent: true}, nil
	}
	if err != nil {
		return State{}, err
	}
	if n.Mode()&0xf000 != 0x8000 || n.Links() != 1 {
		return State{}, fmt.Errorf("destination must be an unshared regular file: %s", p)
	}
	h := sha256.New()
	if err = im.Data(n, h); err != nil {
		return State{}, err
	}
	return State{SHA256: hex.EncodeToString(h.Sum(nil)), Size: n.Size(), Mode: n.Mode() & 07777, UID: n.UID(), GID: n.GID()}, nil
}
func accepted(s State, op Operation) bool {
	if s.Absent {
		return op.AllowAbsent
	}
	if s.SHA256 == op.SHA256 {
		return true
	}
	for _, h := range op.OriginalSHA256 {
		if h == s.SHA256 {
			return true
		}
	}
	return false
}
func NewPlan(input, catalog, profilePath string) (Plan, error) {
	var profile Profile
	if _, err := readJSON(profilePath, &profile); err != nil {
		return Plan{}, err
	}
	return planProfile(input, catalog, profile)
}
func planProfile(input, catalog string, profile Profile) (Plan, error) {
	var plan Plan
	c, err := Load(catalog)
	if err != nil {
		return plan, err
	}
	packages, err := c.resolve(profile, false)
	if err != nil {
		return plan, err
	}
	input, err = filepath.Abs(input)
	if err != nil {
		return plan, err
	}
	st, err := os.Lstat(input)
	if err != nil {
		return plan, err
	}
	if !st.Mode().IsRegular() {
		return plan, fmt.Errorf("input must be a regular file")
	}
	h, n, err := fileHash(input)
	if err != nil {
		return plan, err
	}
	plan = Plan{SchemaVersion: 1, Input: Input{Path: input, SHA256: h, Size: n}, Catalog: c.Root, Profile: profile, Packages: []PackageLock{}, Actions: []Action{}}
	err = openImage(input, func(im *qnx6.Image, format string) error {
		plan.Input.Format = format
		owners := map[string]string{}
		for _, pkg := range packages {
			m := pkg.Manifest
			plan.Packages = append(plan.Packages, PackageLock{m.ID, m.Version, pkg.Directory, pkg.ManifestSHA256})
			for _, a := range m.Assertions {
				p, err := resolveTarget(im, a.Path)
				if err != nil {
					return err
				}
				s, err := inspect(im, p)
				if err != nil {
					return err
				}
				if s.Absent || s.SHA256 != a.SHA256 {
					return fmt.Errorf("%s prerequisite SHA256 mismatch: %s", m.ID, p)
				}
				plan.Actions = append(plan.Actions, Action{Package: m.ID, Path: p, Before: s, AssertionSHA256: a.SHA256})
			}
			for _, op := range m.Operations {
				p, err := resolveTarget(im, op.Path)
				if err != nil {
					return err
				}
				for other, owner := range owners {
					if p == other || strings.HasPrefix(p, other+"/") || strings.HasPrefix(other, p+"/") {
						return fmt.Errorf("file ownership conflict: %s (%s / %s)", p, owner, m.ID)
					}
				}
				owners[p] = m.ID
				s, err := inspect(im, p)
				if err != nil {
					return err
				}
				if !accepted(s, op) {
					return fmt.Errorf("%s original SHA256 not accepted: %s", m.ID, p)
				}
				copyOp := op
				plan.Actions = append(plan.Actions, Action{Package: m.ID, Path: p, Before: s, Operation: &copyOp})
			}
		}
		// Assertions remain true after the transaction; an operation cannot replace
		// an asserted prerequisite with different content.
		for _, a := range plan.Actions {
			if a.Operation == nil {
				for _, b := range plan.Actions {
					if b.Operation != nil && (a.Path == b.Path || strings.HasPrefix(a.Path, b.Path+"/")) {
						return fmt.Errorf("operation overlaps prerequisite assertion: %s", a.Path)
					}
				}
			}
		}
		return nil
	})
	return plan, err
}
func WritePlan(filename string, p Plan) error {
	return atomicfile.Write(filename, func(f *os.File) error { e := json.NewEncoder(f); e.SetIndent("", "  "); return e.Encode(p) })
}

// copyVerified checks the bytes that actually enter the transaction, avoiding a
// separate check/use window for mutable payloads or source images.
func copyVerified(source, target, expected string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("source is not regular")
	}
	return atomicfile.Write(target, func(out *os.File) error {
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(out, h), f); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != expected {
			return fmt.Errorf("locked source SHA256 changed: %s", source)
		}
		return nil
	})
}
