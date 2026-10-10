package rcfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/qnx6"
	"github.com/woozymasta/lzo"
)

func packed(data []byte, compressed bool) ([]byte, error) {
	if !compressed || len(data) == 0 {
		return data, nil
	}
	count := (len(data) + chunkSize - 1) / chunkSize
	b := make([]byte, 4*(count+1))
	for i := 0; i < count; i++ {
		binio.Put32(b, i*4, uint32(len(b)))
		c, err := lzo.Compress(data[i*chunkSize:min((i+1)*chunkSize, len(data))], &lzo.CompressOptions{Level: 9})
		if err != nil {
			return nil, err
		}
		b = append(b, c...)
	}
	binio.Put32(b, count*4, uint32(len(b)))
	return b, nil
}

type ModifyReport struct {
	Commands               int
	IntentionallyCorrupted []string
	ExternalSignature      string
}

func Modify(input, output, script, corrupt string) (ModifyReport, error) {
	report := ModifyReport{ExternalSignature: "not authenticated", IntentionallyCorrupted: []string{}}
	var commands []qnx6.Command
	base := "."
	if script != "" {
		b, err := os.ReadFile(script)
		if err != nil {
			return report, err
		}
		commands, err = qnx6.ParseCommands(b, "push", "chmod", "corrupt")
		if err != nil {
			return report, err
		}
		base = filepath.Dir(script)
	}
	if corrupt != "" {
		commands = append(commands, qnx6.Command{Args: []string{"corrupt", corrupt}})
	}
	if len(commands) == 0 {
		return report, fmt.Errorf("script or corrupt target required")
	}
	f, err := os.Open(input)
	if err != nil {
		return report, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return report, err
	}
	im, err := Open(binio.Reader{ReaderAt: f, Size: st.Size()})
	if err != nil {
		return report, err
	}
	if _, err = im.Verify(); err != nil {
		return report, err
	}
	// Edits may use only each original packed extent. Check overlap before
	// changing anything; this also rejects aliasing another inode's payload.
	type extent struct{ start, end uint64 }
	var extents []extent
	capacities := map[uint32]uint32{}
	for i := uint32(1); i <= im.Count; i++ {
		n, err := im.Node(i)
		if err != nil {
			return report, err
		}
		if n.Mode&0xf000 == 0x4000 || n.Size == 0 {
			continue
		}
		size, err := im.PackedSize(n)
		if err != nil {
			return report, err
		}
		capacities[i] = size
		if n.Offset < im.DataOffset || uint64(n.Offset)+uint64(size) > uint64(im.DataOffset)+uint64(im.DataSize) {
			return report, fmt.Errorf("RCFS data outside data region")
		}
		extents = append(extents, extent{uint64(n.Offset), uint64(n.Offset) + uint64(size)})
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
	for i := 1; i < len(extents); i++ {
		if extents[i].start < extents[i-1].end {
			return report, fmt.Errorf("overlapping RCFS payload extents")
		}
	}
	err = atomicfile.Write(output, func(work *os.File) error {
		if _, err := io.CopyN(work, io.NewSectionReader(f, 0, st.Size()), st.Size()); err != nil {
			return err
		}
		working, err := Open(binio.Reader{ReaderAt: work, Size: st.Size()})
		if err != nil {
			return err
		}
		corrupted := map[uint32]bool{}
		expected := map[uint32][32]byte{}
		for _, c := range commands {
			fail := func(err error) error { return fmt.Errorf("RCFS script line %d (%s): %w", c.Line, c.Args[0], err) }
			args := c.Args[1:]
			if len(args) != 2 && c.Args[0] != "corrupt" || c.Args[0] == "corrupt" && len(args) != 1 {
				return fail(fmt.Errorf("wrong arguments"))
			}
			dst := args[len(args)-1]
			n, err := working.Resolve(dst)
			if err != nil {
				return fail(err)
			}
			if n.Index == working.Verifier.Index {
				return fail(fmt.Errorf("verifier.log cannot be edited directly"))
			}
			if c.Args[0] == "chmod" {
				mode, err := strconv.ParseUint(args[0], 8, 12)
				if err != nil {
					return fail(err)
				}
				binio.LE.PutUint16(n.Raw[4:], n.Mode&0xf000|uint16(mode))
				if _, err = work.WriteAt(n.Raw, int64(working.InodeOffset)+int64(n.Index-1)*32); err != nil {
					return err
				}
			} else {
				if n.Mode&0xf000 != 0x8000 {
					return fail(fmt.Errorf("target must be regular file"))
				}
				if c.Args[0] == "corrupt" {
					if n.Size == 0 {
						return fail(fmt.Errorf("cannot corrupt empty file"))
					}
					b, err := working.R.Bytes(int64(n.Offset), 1)
					if err != nil {
						return err
					}
					b[0] ^= 0xff
					if _, err = work.WriteAt(b, int64(n.Offset)); err != nil {
						return err
					}
					corrupted[n.Index] = true
					delete(expected, n.Index)
					report.IntentionallyCorrupted = append(report.IntentionallyCorrupted, dst)
				} else {
					source := args[0]
					if !filepath.IsAbs(source) {
						source = filepath.Join(base, source)
					}
					sourceInfo, err := os.Lstat(source)
					if err != nil {
						return fail(err)
					}
					if !sourceInfo.Mode().IsRegular() || sourceInfo.Size() > 64<<20 {
						return fail(fmt.Errorf("replacement must be regular file <=64 MiB"))
					}
					data, err := os.ReadFile(source)
					if err != nil {
						return fail(err)
					}
					encoded, err := packed(data, n.Extended>>7 == 1)
					if err != nil {
						return fail(err)
					}
					if len(encoded) > int(capacities[n.Index]) {
						return fail(fmt.Errorf("replacement exceeds allocated packed extent"))
					}
					if _, err = work.WriteAt(encoded, int64(n.Offset)); err != nil {
						return err
					}
					binio.Put32(n.Raw, 16, uint32(len(data)))
					if _, err = work.WriteAt(n.Raw, int64(working.InodeOffset)+int64(n.Index-1)*32); err != nil {
						return err
					}
					v := working.Hashes[n.Index]
					hash := sha256.Sum256(encoded)
					record, err := working.R.Bytes(v.Offset, 48)
					if err != nil {
						return err
					}
					binio.Put32(record, 8, uint32(len(encoded)))
					copy(record[12:44], hash[:])
					if _, err = work.WriteAt(record, v.Offset); err != nil {
						return err
					}
					expected[n.Index] = sha256.Sum256(data)
					delete(corrupted, n.Index)
				}
			}
			report.Commands++
		}
		working, err = Open(binio.Reader{ReaderAt: work, Size: st.Size()})
		if err != nil {
			return err
		}
		if _, err = working.verify(corrupted); err != nil {
			return err
		}
		for index, hash := range expected {
			n, err := working.Node(index)
			if err != nil {
				return err
			}
			h := sha256.New()
			if err = working.Data(n, h); err != nil {
				return err
			}
			if !bytes.Equal(h.Sum(nil), hash[:]) {
				return fmt.Errorf("replacement read-back hash mismatch")
			}
		}
		return nil
	})
	return report, err
}
