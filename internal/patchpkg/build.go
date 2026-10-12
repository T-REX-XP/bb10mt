package patchpkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bb10root/bb10mt/internal/atomicfile"
	"github.com/bb10root/bb10mt/internal/batch"
	"github.com/bb10root/bb10mt/internal/qnx6"
)

type BuildReport struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Input          Input             `json:"input"`
	Packages       []PackageLock     `json:"packages"`
	Files          int               `json:"files"`
	AlreadyPresent int               `json:"alreadyPresent"`
	Outputs        map[string]string `json:"outputSha256"`
	Checks         []string          `json:"checks"`
}

// quoteScript matches the existing parser's literal quoting, not shell or JSON
// escaping. Package paths cannot contain quotes; host directories may contain one.
func quoteScript(p string) (string, error) {
	p = filepath.ToSlash(p)
	if strings.ContainsAny(p, "\r\n\x00") {
		return "", fmt.Errorf("unsupported host path")
	}
	for _, quote := range []string{"\"", "'"} {
		if !strings.Contains(p, quote) {
			return quote + p + quote, nil
		}
	}
	return "", fmt.Errorf("host path contains both quote characters")
}
func expectedRows(plan Plan) []qnx6.Expected {
	rows := make([]qnx6.Expected, 0, len(plan.Actions))
	for _, a := range plan.Actions {
		if a.Operation == nil {
			rows = append(rows, qnx6.Expected{Path: a.Path, SHA256: a.AssertionSHA256, Mode: &a.Before.Mode, UID: &a.Before.UID, GID: &a.Before.GID})
			continue
		}
		op := a.Operation
		n, _ := strconv.ParseUint(op.Mode, 8, 16)
		mode := uint16(n)
		rows = append(rows, qnx6.Expected{Path: a.Path, SHA256: op.SHA256, Mode: &mode, UID: &op.UID, GID: &op.GID})
	}
	return rows
}
func apply(plan Plan, catalog, work, input, output string, log io.Writer) error {
	var script strings.Builder
	directories := map[string]string{}
	for _, p := range plan.Packages {
		directories[p.ID] = p.Directory
	}
	if err := openImage(input, func(im *qnx6.Image, _ string) error {
		for _, a := range plan.Actions {
			state, err := inspect(im, a.Path)
			if err != nil {
				return err
			}
			if state != a.Before {
				return fmt.Errorf("locked precondition changed: %s", a.Path)
			}
			if a.Operation == nil {
				continue
			}
			op := a.Operation
			if state.Absent || state.SHA256 != op.SHA256 {
				source, err := regularPath(filepath.Join(catalog, directories[a.Package]), op.Source)
				if err != nil {
					return err
				}
				quoted, err := quoteScript(source)
				if err != nil {
					return err
				}
				if op.Type == "binary-patch" {
					fmt.Fprintf(&script, "binarypatch %s %s\n", a.Path, quoted)
				} else {
					fmt.Fprintf(&script, "mkdir -p %s\n", path.Dir(a.Path))
					if !state.Absent {
						fmt.Fprintf(&script, "rm %s\n", a.Path)
					}
					fmt.Fprintf(&script, "push %s %s\n", quoted, a.Path)
				}
			}
			fmt.Fprintf(&script, "chmod %s %s\nchown %d:%d %s\n", op.Mode, a.Path, op.UID, op.GID, a.Path)
		}
		return nil
	}); err != nil {
		return err
	}
	p := filepath.Join(work, "operations.txt")
	if err := os.WriteFile(p, []byte(script.String()), 0600); err != nil {
		return err
	}
	if err := qnx6.Script(input, p, output, log); err != nil {
		return err
	}
	return openImage(output, func(im *qnx6.Image, _ string) error {
		if err := im.VerifyPayloads(expectedRows(plan)); err != nil {
			return err
		}
		check, err := im.Check()
		if err != nil {
			return err
		}
		if len(check.Errors) > 0 {
			return fmt.Errorf("final filesystem check: %s", check.Errors[0])
		}
		return nil
	})
}

func Build(planFile, output string, log io.Writer) error {
	// MkdirTemp preserves a relative parent. Make generated payload/script paths
	// absolute so the script adapter never resolves them twice against its base.
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if log == nil {
		log = io.Discard
	}
	var plan Plan
	if _, err := readJSON(planFile, &plan); err != nil {
		return err
	}
	if plan.SchemaVersion != 1 || !validHash(plan.Input.SHA256) || (plan.Input.Format != "qnx6" && plan.Input.Format != "cap") {
		return fmt.Errorf("invalid package lock")
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	c, err := Load(plan.Catalog)
	if err != nil {
		return err
	}
	packages, err := c.resolve(plan.Profile, false)
	if err != nil {
		return err
	}
	locked := map[string]PackageLock{}
	for _, p := range plan.Packages {
		if _, ok := locked[p.ID]; ok {
			return fmt.Errorf("duplicate locked package")
		}
		locked[p.ID] = p
	}
	work, err := os.MkdirTemp(filepath.Dir(output), ".bb10mt-packages-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	// Keep firmware packing beside the build transaction (D:\tmp for maintained
	// builds), rather than silently consuming the system temporary volume.
	inputDir, err := os.MkdirTemp(work, "input-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(inputDir)
	input := filepath.Join(inputDir, filepath.Base(plan.Input.Path))
	if err = copyVerified(plan.Input.Path, input, plan.Input.SHA256); err != nil {
		return err
	}
	catalog := filepath.Join(work, "catalog")
	if err = os.Mkdir(catalog, 0700); err != nil {
		return err
	}
	for _, pkg := range packages {
		lock, ok := locked[pkg.Manifest.ID]
		if !ok || lock.ManifestSHA256 != pkg.ManifestSHA256 {
			return fmt.Errorf("locked manifest changed: %s", pkg.Manifest.ID)
		}
		dir := filepath.Join(catalog, pkg.Directory)
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
		mf, err := regularPath(filepath.Join(c.Root, pkg.Directory), "manifest.json")
		if err != nil {
			return err
		}
		if err = copyVerified(mf, filepath.Join(dir, "manifest.json"), lock.ManifestSHA256); err != nil {
			return err
		}
		copied := map[string]bool{}
		for _, op := range pkg.Manifest.Operations {
			if copied[op.Source] {
				continue
			}
			copied[op.Source] = true
			p, err := regularPath(filepath.Join(c.Root, pkg.Directory), op.Source)
			if err != nil {
				return err
			}
			target := filepath.Join(dir, filepath.FromSlash(op.Source))
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			if err = copyVerified(p, target, op.payloadHash()); err != nil {
				return err
			}
		}
	}
	regenerated, err := planProfile(input, catalog, plan.Profile)
	if err != nil {
		return err
	}
	regenerated.Input.Path = plan.Input.Path
	regenerated.Catalog = plan.Catalog
	a, _ := json.Marshal(plan)
	b, _ := json.Marshal(regenerated)
	if !bytes.Equal(a, b) {
		return fmt.Errorf("locked plan does not match regenerated plan; create a new plan")
	}
	result := filepath.Join(work, "result")
	transform := func(source, target string) error { return apply(plan, catalog, work, source, target, log) }
	checks := []string{"locked input, manifests and payload SHA256", "regenerated dependency/ownership plan", "original file preconditions", "final payload SHA256/mode/uid/gid", "foundation unchanged", "final filesystem and long-name checksums"}
	if plan.Input.Format == "cap" {
		if err = batch.BuildWithTransform(input, result, log, batch.Options{}, transform, checks); err != nil {
			return err
		}
		// The batch transaction reads the pinned private input. Its delivered
		// report should identify the user's retained input, not a deleted temp file.
		var containerReport batch.Report
		p := filepath.Join(result, "build-report.json")
		if _, err = readJSON(p, &containerReport); err != nil {
			return err
		}
		containerReport.Input = plan.Input.Path
		data, err := json.MarshalIndent(containerReport, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(p, append(data, '\n'), 0644); err != nil {
			return err
		}
	} else {
		if err = os.Mkdir(result, 0700); err != nil {
			return err
		}
		repaired := filepath.Join(work, "repaired.ufs")
		if _, err = qnx6.Repair(input, repaired); err != nil {
			return err
		}
		if err = transform(repaired, filepath.Join(result, "firmware.ufs")); err != nil {
			return err
		}
	}
	if err = WritePlan(filepath.Join(result, "plan.json"), plan); err != nil {
		return err
	}
	report := BuildReport{SchemaVersion: 1, Input: plan.Input, Packages: plan.Packages, Outputs: map[string]string{}, Checks: checks}
	for _, action := range plan.Actions {
		if action.Operation != nil {
			report.Files++
			if action.Before.SHA256 == action.Operation.SHA256 {
				report.AlreadyPresent++
			}
		}
	}
	entries, err := os.ReadDir(result)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("unexpected output directory")
		}
		h, _, err := fileHash(filepath.Join(result, entry.Name()))
		if err != nil {
			return err
		}
		report.Outputs[entry.Name()] = h
	}
	if err = atomicfile.Write(filepath.Join(result, "package-report.json"), func(f *os.File) error { e := json.NewEncoder(f); e.SetIndent("", "  "); return e.Encode(report) }); err != nil {
		return err
	}
	return atomicfile.PublishDirectory(result, output)
}
