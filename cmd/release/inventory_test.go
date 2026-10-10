package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestInventoryOmitsHostPathsAndIncludesDependencies(t *testing.T) {
	a := []byte(`{"Path":"github.com/bb10root/bb10mt","Main":true,"Dir":"C:\\private","GoVersion":"1.26.0"}
{"Path":"github.com/woozymasta/lzo","Version":"v0.3.2","Sum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","Dir":"/host/cache"}`)
	b := []byte(`{"Path":"github.com/woozymasta/lzo","Version":"v0.3.2","Sum":"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","Dir":"/different/cache"}
{"Path":"github.com/bb10root/bb10mt","Main":true,"Dir":"/different/repo","GoVersion":"1.26.0"}`)
	inv, sbom, err := dependencyArtifacts(a, "v0.7.0-go.1", "go1.26.5")
	if err != nil {
		t.Fatal(err)
	}
	inv2, sbom2, err := dependencyArtifacts(b, "v0.7.0-go.1", "go1.26.5")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inv, inv2) || !bytes.Equal(sbom, sbom2) || bytes.Contains(inv, []byte("private")) {
		t.Fatal("host-dependent inventory")
	}
	var parsed map[string]any
	if err = json.Unmarshal(sbom, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed["components"].([]any)) != 2 {
		t.Fatal("dependency missing")
	}
	if _, _, err = dependencyArtifacts([]byte(`{"Path":"unknown","Version":"v1"}`), "v1", "go1"); err == nil {
		t.Fatal("unknown license accepted")
	}
}

func TestInventoryRejectsMissingOrInvalidModuleHash(t *testing.T) {
	for _, sum := range []string{"", "h1:abc", "unknown:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		data, _ := json.Marshal(module{Path: "github.com/woozymasta/lzo", Version: "v0.3.2", Sum: sum})
		if _, _, e := dependencyArtifacts(data, "v0.7.0-go.1", "go1.27.2"); e == nil {
			t.Fatal("invalid module checksum accepted", sum)
		}
	}
}
