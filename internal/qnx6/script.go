package qnx6

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

type Command struct {
	Line int
	Args []string
}

func ParseScript(data []byte) ([]Command, error) {
	return ParseCommands(data, "mkdir", "touch", "push", "chmod", "chown", "replace", "rm", "addstring", "removeapp")
}

func ParseCommands(data []byte, allowed ...string) ([]Command, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var commands []Command
	line := 0
	for scanner.Scan() {
		line++
		s := strings.TrimPrefix(scanner.Text(), "\ufeff")
		var args []string
		var word strings.Builder
		quote := byte(0)
		started := false
		flush := func() {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					word.WriteByte(c)
				}
				continue
			}
			if c == '#' {
				break
			}
			if c == '\'' || c == '"' {
				quote = c
				started = true
				continue
			}
			if c == ' ' || c == '\t' || c == '\r' {
				flush()
				continue
			}
			word.WriteByte(c)
			started = true
		}
		if quote != 0 {
			return nil, fmt.Errorf("script line %d: unterminated quote", line)
		}
		flush()
		if len(args) == 0 {
			continue
		}
		known := false
		for _, name := range allowed {
			if args[0] == name {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("script line %d: unknown command %q", line, args[0])
		}
		commands = append(commands, Command{line, args})
	}
	return commands, scanner.Err()
}
func (e *Editor) readSmall(p string) ([]byte, error) {
	n, _, err := e.Resolve(p)
	if err != nil {
		return nil, err
	}
	if n.Size() > 64<<20 || n.Mode()&0xf000 != 0x8000 {
		return nil, fmt.Errorf("text command requires regular file <=64 MiB")
	}
	var b bytes.Buffer
	if err = e.Data(n, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func (e *Editor) walk(p string, fn func(Node) error) error {
	visited := map[uint32]bool{}
	var visit func(string) error
	visit = func(p string) error {
		n, _, err := e.Resolve(p)
		if err != nil {
			return err
		}
		if visited[n.Number] {
			return nil
		}
		visited[n.Number] = true
		if err = fn(n); err != nil {
			return err
		}
		if n.Mode()&0xf000 != 0x4000 {
			return nil
		}
		entries, err := e.Entries(n)
		if err != nil {
			return err
		}
		for _, v := range entries {
			if v.Name == "." || v.Name == ".." {
				continue
			}
			if err = visit(path.Join(p, v.Name)); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(p)
}
func (e *Editor) push(source, dest string) ([]Expected, error) {
	var expected []Expected
	st, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink source unsupported: %s", source)
	}
	trailingSlash := strings.HasSuffix(dest, "/")
	dest, err = canonical(strings.TrimSuffix(dest, "/"))
	if err != nil {
		return nil, err
	}
	pushFile := func(src, dst string) error {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("push source is not regular")
		}
		h := sha256.New()
		if n, _, found := e.Resolve(dst); found == nil {
			if n.Mode()&0xf000 != 0x8000 || n.Size() != uint64(st.Size()) {
				return fmt.Errorf("push destination exists with different content: %s", dst)
			}
			sourceHash := sha256.New()
			if _, err = io.Copy(sourceHash, f); err != nil {
				return err
			}
			imageHash := sha256.New()
			if err = e.Data(n, imageHash); err != nil {
				return err
			}
			if !bytes.Equal(sourceHash.Sum(nil), imageHash.Sum(nil)) {
				return fmt.Errorf("push destination exists with different content: %s", dst)
			}
			expected = append(expected, Expected{Path: dst, SHA256: fmt.Sprintf("%x", sourceHash.Sum(nil))})
			return nil
		}
		if err = e.WriteFile(dst, io.TeeReader(f, h), uint64(st.Size()), true); err != nil {
			return err
		}
		expected = append(expected, Expected{Path: dst, SHA256: fmt.Sprintf("%x", h.Sum(nil))})
		return nil
	}
	if !st.IsDir() {
		if trailingSlash {
			dest = path.Join(dest, filepath.Base(source))
		}
		err = pushFile(source, dest)
		return expected, err
	}
	if trailingSlash {
		dest = path.Join(dest, filepath.Base(source))
	}
	if err = e.Mkdir(dest, true); err != nil {
		return nil, err
	}
	err = filepath.WalkDir(source, func(local string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, local)
		if err != nil {
			return err
		}
		target := dest
		if rel != "." {
			target = path.Join(dest, filepath.ToSlash(rel))
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink source unsupported: %s", local)
		}
		if d.IsDir() {
			return e.Mkdir(target, true)
		}
		return pushFile(local, target)
	})
	return expected, err
}

func (e *Editor) removeApps(names []string) error {
	apps, _, err := e.Resolve("/apps")
	if err != nil {
		return err
	}
	entries, err := e.Entries(apps)
	if err != nil {
		return err
	}
	matches := func(s string) bool {
		for _, name := range names {
			if s == name || strings.HasPrefix(s, name+".") {
				return true
			}
		}
		return false
	}
	var removed []string
	for _, v := range entries {
		if v.Name == "." || v.Name == ".." {
			continue
		}
		if matches(v.Name) {
			if err = e.Remove("/apps/"+v.Name, true); err != nil {
				return err
			}
			removed = append(removed, v.Name)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	reg := "/var/pps/system/installer/registeredapps/applications"
	files := []string{reg}
	details, _, err := e.Resolve("/var/pps/system/installer/appdetails")
	if err != nil {
		return err
	}
	rows, err := e.Entries(details)
	if err != nil {
		return err
	}
	for _, v := range rows {
		if v.Name != "." && v.Name != ".." {
			files = append(files, "/var/pps/system/installer/appdetails/"+v.Name)
		}
	}
	for _, p := range files {
		b, err := e.readSmall(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		keep := []string{}
		changed := false
		for _, line := range lines {
			drop := false
			for _, name := range removed {
				if strings.Contains(line, name) {
					drop = true
					break
				}
			}
			if drop {
				changed = true
			} else {
				keep = append(keep, line)
			}
		}
		if changed {
			b = []byte(strings.Join(keep, "\n"))
			if err = e.WriteFile(p, bytes.NewReader(b), uint64(len(b)), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Editor) execute(c Command, base string) ([]Expected, error) {
	a := c.Args[1:]
	fail := func() ([]Expected, error) { return nil, fmt.Errorf("invalid arguments for %s", c.Args[0]) }
	switch c.Args[0] {
	case "mkdir":
		parents := false
		if len(a) > 0 && a[0] == "-p" {
			parents = true
			a = a[1:]
		}
		if len(a) != 1 {
			return fail()
		}
		return nil, e.Mkdir(a[0], parents)
	case "touch":
		if len(a) != 1 {
			return fail()
		}
		if n, _, err := e.Resolve(a[0]); err == nil {
			if n.Mode()&0xf000 != 0x8000 {
				return nil, fmt.Errorf("touch target is not a regular file")
			}
			return nil, nil
		}
		return nil, e.WriteFile(a[0], bytes.NewReader(nil), 0, true)
	case "push":
		if len(a) != 2 {
			return fail()
		}
		source := a[0]
		if !filepath.IsAbs(source) {
			source = filepath.Join(base, source)
		}
		return e.push(source, a[1])
	case "rm":
		recursive, force := false, false
		for len(a) > 0 && strings.HasPrefix(a[0], "-") {
			switch a[0] {
			case "-r", "-R":
				recursive = true
			case "-f":
				force = true
			case "-rf", "-fr":
				recursive = true
				force = true
			default:
				return fail()
			}
			a = a[1:]
		}
		if len(a) == 0 {
			return fail()
		}
		for _, p := range a {
			if _, err := canonical(p); err != nil {
				return nil, err
			}
			if force {
				if _, _, err := e.Resolve(p); err != nil {
					if errors.Is(err, ErrNotFound) {
						continue
					}
					return nil, err
				}
			}
			if err := e.Remove(p, recursive); err != nil {
				return nil, err
			}
		}
		return nil, nil
	case "chmod", "chown":
		recursive := false
		if len(a) > 0 && a[0] == "-R" {
			recursive = true
			a = a[1:]
		}
		if len(a) != 2 {
			return fail()
		}
		var fn func(Node) error
		if c.Args[0] == "chmod" {
			v, err := strconv.ParseUint(a[0], 8, 12)
			if err != nil {
				return nil, err
			}
			fn = func(n Node) error { binio.LE.PutUint16(n.Raw[32:], n.Mode()&0xf000|uint16(v)); return e.setNode(n) }
		} else {
			owner, group, has := strings.Cut(a[0], ":")
			var uid, gid *uint32
			for i, s := range []string{owner, group} {
				if s == "" {
					continue
				}
				v, err := strconv.ParseUint(s, 10, 32)
				if err != nil {
					return nil, err
				}
				p := uint32(v)
				if i == 0 {
					uid = &p
				} else {
					gid = &p
				}
			}
			if uid == nil && gid == nil || !has && owner == "" {
				return fail()
			}
			fn = func(n Node) error {
				if uid != nil {
					binio.Put32(n.Raw, 8, *uid)
				}
				if gid != nil {
					binio.Put32(n.Raw, 12, *gid)
				}
				return e.setNode(n)
			}
		}
		if recursive {
			return nil, e.walk(a[1], fn)
		}
		n, _, err := e.Resolve(a[1])
		if err != nil {
			return nil, err
		}
		return nil, fn(n)
	case "replace", "addstring":
		need := 3
		if c.Args[0] == "addstring" {
			need = 2
		}
		if len(a) != need {
			return fail()
		}
		b, err := e.readSmall(a[0])
		if err != nil {
			return nil, err
		}
		if c.Args[0] == "replace" {
			if a[1] == "" {
				return nil, fmt.Errorf("empty replace pattern")
			}
			b = bytes.ReplaceAll(b, []byte(a[1]), []byte(a[2]))
		} else {
			for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
				if line == a[1] {
					return nil, nil
				}
			}
			if len(b) > 0 && b[len(b)-1] != '\n' {
				b = append(b, '\n')
			}
			b = append(b, []byte(a[1]+"\n")...)
		}
		if err = e.WriteFile(a[0], bytes.NewReader(b), uint64(len(b)), false); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		p, err := canonical(a[0])
		return []Expected{{Path: p, SHA256: fmt.Sprintf("%x", sum)}}, err
	case "removeapp":
		if len(a) == 0 {
			return fail()
		}
		for _, name := range a {
			if name == "" || strings.ContainsAny(name, "/\\") {
				return fail()
			}
		}
		return nil, e.removeApps(a)
	}
	return nil, fmt.Errorf("unknown command")
}

// Script applies all commands to a temporary sibling, checks the filesystem and
// every pushed payload, and publishes a new output image only on success.
func Script(input, script, output string, log io.Writer) error {
	return ScriptWithOptions(input, script, output, log, ScriptOptions{})
}

type ScriptOptions struct {
	Debloat   bool
	Blacklist []string
}

func ScriptWithOptions(input, script, output string, log io.Writer, opt ScriptOptions) error {
	var data []byte
	var err error
	if script != "" {
		data, err = os.ReadFile(script)
		if err != nil {
			return err
		}
	} else if !opt.Debloat {
		return fmt.Errorf("script or debloat option required")
	}
	var debloat []byte
	if opt.Debloat {
		debloat, err = DebloatList(opt.Blacklist)
		if err != nil {
			return err
		}
	}
	commands, err := ParseScript(data)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(filepath.Dir(script))
	if err != nil {
		return err
	}
	source, err := os.Open(input)
	if err != nil {
		return err
	}
	defer source.Close()
	st, err := source.Stat()
	if err != nil {
		return err
	}
	return atomicfile.Write(output, func(f *os.File) error {
		if _, err := io.CopyN(f, io.NewSectionReader(source, 0, st.Size()), st.Size()); err != nil {
			return err
		}
		editor, err := NewEditor(f)
		if err != nil {
			return err
		}
		// Preexisting name defects must be repaired explicitly first. Other
		// structural errors are fatal; stale free counters are recomputed at commit.
		baseline, err := editor.Check()
		if err != nil {
			return err
		}
		for _, problem := range baseline.Errors {
			if problem != "free block count mismatch" && problem != "free inode count mismatch" {
				return fmt.Errorf("source filesystem invalid: %s", problem)
			}
		}
		expected := map[string]Expected{}
		for _, c := range commands {
			rows, err := editor.execute(c, base)
			if err != nil {
				return fmt.Errorf("script line %d (%s): %w", c.Line, c.Args[0], err)
			}
			for _, v := range rows {
				expected[v.Path] = v
			}
			if c.Args[0] == "rm" || c.Args[0] == "removeapp" {
				for p := range expected {
					if _, _, err := editor.Resolve(p); errors.Is(err, ErrNotFound) {
						delete(expected, p)
					} else if err != nil {
						return err
					}
				}
			}
			if _, err = fmt.Fprintf(log, "line %d: %s OK\n", c.Line, c.Args[0]); err != nil {
				return err
			}
		}
		if len(debloat) > 0 {
			const p = "/accounts/devuser/rootdata/debloat.txt"
			if err = editor.Mkdir("/accounts/devuser/rootdata", true); err != nil {
				return err
			}
			if err = editor.WriteFile(p, bytes.NewReader(debloat), uint64(len(debloat)), false); err != nil {
				return err
			}
			n, _, err := editor.Resolve(p)
			if err != nil {
				return err
			}
			binio.LE.PutUint16(n.Raw[32:], 0x8000|0777)
			if err = editor.setNode(n); err != nil {
				return err
			}
			sum := sha256.Sum256(debloat)
			expected[p] = Expected{Path: p, SHA256: fmt.Sprintf("%x", sum)}
		}
		if err = editor.Commit(); err != nil {
			return err
		}
		rows := []Expected{}
		for _, v := range expected {
			n, _, err := editor.Resolve(v.Path)
			if err != nil {
				return err
			}
			mode := n.Mode() & 07777
			uid, gid := n.UID(), n.GID()
			v.Mode = &mode
			v.UID = &uid
			v.GID = &gid
			rows = append(rows, v)
		}
		return editor.VerifyPayloads(rows)
	})
}
