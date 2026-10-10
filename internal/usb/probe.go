package usb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bb10root/bb10mt/internal/binio"
	"github.com/bb10root/bb10mt/internal/loaderarchive"
)

type ProbeResult struct {
	Loader  string `json:"loader"`
	ModelID uint32 `json:"modelID"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

type probeCandidate struct{ name, file, resource string }

// ProbeLoaders tries each distinct file or archive resource once. A transport,
// authentication or initialization failure stops the entire operation. Only
// structurally incompatible candidates are skipped. Every successful loader is
// rebooted; returning to BootROM for the next candidate has a bounded wait.
func ProbeLoaders(ctx context.Context, backend Backend, o Options, emit func(ProbeResult) error) (err error) {
	if o.LoaderFile != "" {
		return fmt.Errorf("probe-all cannot be combined with loader-file")
	}
	if emit == nil {
		return fmt.Errorf("probe result callback required")
	}
	var archive *loaderarchive.Archive
	if o.LoaderArchive != "" {
		f, e := os.Open(o.LoaderArchive)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, f.Close()) }()
		st, e := f.Stat()
		if e != nil {
			return e
		}
		archive, e = loaderarchive.Read(binio.Reader{ReaderAt: f, Size: st.Size()})
		if e != nil {
			return e
		}
	}
	candidates, e := probeCandidates(o, archive)
	if e != nil {
		return e
	}
	s, e := OpenBoot(ctx, backend, o)
	if e != nil {
		return e
	}
	defer func() {
		if s != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	model, bus := s.Info.ModelID, int(s.Device.Bus)
	success := 0
	for _, candidate := range candidates {
		if e = ctx.Err(); e != nil {
			return e
		}
		var data []byte
		if candidate.file != "" {
			data, e = readLoader(candidate.file, model)
			var pathErr *os.PathError
			if errors.As(e, &pathErr) {
				return e
			}
		} else {
			data, e = archive.Extract(candidate.resource)
			if e != nil {
				return e
			}
			_, e = ValidateLoader(data, model)
		}
		if e != nil {
			if e = emit(ProbeResult{Loader: candidate.name, ModelID: model, Status: "skipped", Reason: e.Error()}); e != nil {
				return e
			}
			continue
		}
		if s == nil {
			next := o
			next.Bus, next.Address = bus, -1
			s, e = OpenBoot(ctx, backend, next)
			if e != nil {
				return e
			}
			if s.Info.ModelID != model {
				return fmt.Errorf("device model changed during probing")
			}
		}
		if e = s.startLoaderData(ctx, backend, o, data, candidate.name); e != nil {
			return fmt.Errorf("probe %s: %w", candidate.name, e)
		}
		if e = s.Reboot(); e != nil {
			return e
		}
		if e = s.Close(); e != nil {
			return e
		}
		s = nil
		success++
		if e = emit(ProbeResult{Loader: candidate.name, ModelID: model, Status: "initialized-and-rebooted"}); e != nil {
			return e
		}
	}
	if success == 0 {
		return fmt.Errorf("no compatible loader initialized")
	}
	return nil
}

func probeCandidates(o Options, archive *loaderarchive.Archive) ([]probeCandidate, error) {
	byName := map[string]probeCandidate{}
	if archive != nil {
		for _, entry := range archive.Entries {
			byName[strings.ToLower(entry.Name)] = probeCandidate{name: o.LoaderArchive + ":" + entry.Name, resource: entry.Name}
		}
	}
	dir := o.LoaderDirectory
	if dir == "" {
		dir = "loaders"
	}
	entries, e := os.ReadDir(dir)
	if e != nil && !(os.IsNotExist(e) && archive != nil) {
		return nil, e
	}
	mapped := map[string]bool{}
	if o.Config != "" {
		f, e := os.Open(o.Config)
		if e != nil {
			return nil, e
		}
		m, e := LoaderMap(f)
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		for _, name := range m {
			mapped[strings.ToLower(name)] = true
		}
	}
	for _, entry := range entries {
		key := strings.ToLower(entry.Name())
		if entry.IsDir() || (!strings.HasSuffix(key, ".bin") && !mapped[key]) {
			continue
		}
		resourceKey := strings.TrimSuffix(key, ".bin")
		delete(byName, resourceKey)
		byName[key] = probeCandidate{name: filepath.Join(dir, entry.Name()), file: filepath.Join(dir, entry.Name())}
	}
	if len(byName) == 0 || len(byName) > 256 {
		return nil, fmt.Errorf("probe requires 1..256 unique loader candidates")
	}
	result := make([]probeCandidate, 0, len(byName))
	for _, v := range byName {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result, nil
}
