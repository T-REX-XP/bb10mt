package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Sum, GoVersion string
	Main                          bool
	Replace                       *module `json:",omitempty"`
}

func dependencyArtifacts(data []byte, version, toolchain string) ([]byte, []byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var modules []module
	for {
		var m module
		err := decoder.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if m.Replace != nil {
			return nil, nil, fmt.Errorf("release dependencies cannot use module replacements")
		}
		modules = append(modules, m)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	licenses := map[string]string{"github.com/woozymasta/lzo": "MIT", "github.com/ebitengine/purego": "Apache-2.0", "github.com/ulikunitz/xz": "BSD-3-Clause",
		"github.com/hanwen/go-fuse/v2": "BSD-3-Clause", "golang.org/x/sys": "BSD-3-Clause", "golang.org/x/sync": "BSD-3-Clause",
		"github.com/kylelemons/godebug": "Apache-2.0", "github.com/moby/sys/mountinfo": "Apache-2.0", "github.com/rasky/go-xdr": "ISC", "github.com/willscott/go-nfs-client": "BSD-2-Clause"}
	var components, dependencies []any
	stdlib := map[string]any{"bom-ref": "go-stdlib", "type": "framework", "name": "Go standard library", "version": toolchain, "licenses": []any{map[string]any{"license": map[string]string{"id": "BSD-3-Clause"}}}, "purl": "pkg:golang/stdlib@" + strings.TrimPrefix(toolchain, "go")}
	components = append(components, stdlib)
	refs := []string{"go-stdlib"}
	for i := range modules {
		m := &modules[i]
		if m.Main {
			m.Version = version
			continue
		}
		license, ok := licenses[m.Path]
		if !ok {
			return nil, nil, fmt.Errorf("dependency license/notice inventory missing: %s", m.Path)
		}
		encodedSum, ok := strings.CutPrefix(m.Sum, "h1:")
		decodedSum, err := base64.StdEncoding.DecodeString(encodedSum)
		if !ok || err != nil || len(decodedSum) != 32 || m.Version == "" {
			return nil, nil, fmt.Errorf("dependency version/checksum missing or invalid: %s; run go mod download all", m.Path)
		}
		ref := m.Path + "@" + m.Version
		refs = append(refs, ref)
		component := map[string]any{"bom-ref": ref, "type": "library", "name": m.Path, "version": m.Version, "purl": "pkg:golang/" + ref, "licenses": []any{map[string]any{"license": map[string]string{"id": license}}}, "properties": []any{map[string]string{"name": "go:module:sum", "value": m.Sum}}}
		components = append(components, component)
	}
	dependencies = append(dependencies, map[string]any{"ref": "bb10mt", "dependsOn": refs})
	app := map[string]any{"bom-ref": "bb10mt", "type": "application", "name": "github.com/bb10root/bb10mt", "version": version, "licenses": []any{map[string]any{"license": map[string]string{"id": "GPL-3.0-only"}}}}
	sbom := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": map[string]any{"component": app}, "components": components, "dependencies": dependencies}
	encoded, err := json.MarshalIndent(modules, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	inventory := []byte("# Build dependency inventory\n\nToolchain: " + toolchain + "\n\n```json\n" + string(encoded) + "\n```\n")
	encoded, err = json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return inventory, append(encoded, '\n'), nil
}
