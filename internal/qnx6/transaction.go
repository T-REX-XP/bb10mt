package qnx6

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
)

// Transaction edits a private image copy, checks the complete source and result,
// and publishes only after the supplied service succeeds.
func Transaction(input, output string, edit func(*Editor) error) error {
	source, e := os.Open(input)
	if e != nil {
		return e
	}
	defer source.Close()
	st, e := source.Stat()
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular image")
	}
	return atomicfile.Write(output, func(f *os.File) error {
		if _, e := io.CopyN(f, source, st.Size()); e != nil {
			return e
		}
		editor, e := NewEditor(f)
		if e != nil {
			return e
		}
		check, e := editor.Check()
		if e != nil {
			return e
		}
		if len(check.Errors) > 0 {
			return fmt.Errorf("source filesystem invalid: %s", check.Errors[0])
		}
		if e = edit(editor); e != nil {
			return e
		}
		return editor.Commit()
	})
}
func (e *Editor) SetAttributes(p string, mode uint16, uid, gid uint32) error {
	if mode & ^uint16(07777) != 0 {
		return fmt.Errorf("invalid permission bits")
	}
	n, _, err := e.Resolve(p)
	if err != nil {
		return err
	}
	binio.LE.PutUint16(n.Raw[32:], n.Mode()&0xf000|mode)
	binio.Put32(n.Raw, 8, uid)
	binio.Put32(n.Raw, 12, gid)
	return e.setNode(n)
}
func (im *Image) ReadFile(p string, limit uint64) ([]byte, error) {
	n, _, e := im.Resolve(p)
	if e != nil {
		return nil, e
	}
	if n.Mode()&0xf000 != 0x8000 || n.Size() > limit {
		return nil, fmt.Errorf("invalid regular file size/type: %s", p)
	}
	var b bytes.Buffer
	if e = im.Data(n, &b); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
