package patcher

import (
	"encoding/json"
	"testing"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

func TestBuildTrivyReport_HomogeneousApt(t *testing.T) {
	pkgs := []types.PatchPackage{
		{Name: "libssl3", TargetVersion: "3.0.2-0ubuntu1.10", PackageManager: "apt"},
		{Name: "zlib1g", TargetVersion: "1:1.2.11.dfsg-2ubuntu9.2", PackageManager: "apt"},
	}
	b, err := BuildTrivyReport("docker.io/library/ubuntu:22.04", "ubuntu", pkgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got trivyReport
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", got.SchemaVersion)
	}
	if got.ArtifactName != "docker.io/library/ubuntu:22.04" {
		t.Errorf("ArtifactName = %q", got.ArtifactName)
	}
	if len(got.Results) != 1 {
		t.Fatalf("Results len = %d, want 1", len(got.Results))
	}
	if got.Results[0].Type != "ubuntu" || got.Results[0].Class != "os-pkgs" {
		t.Errorf("Results[0] Type/Class = %q/%q", got.Results[0].Type, got.Results[0].Class)
	}
	if len(got.Results[0].Vulnerabilities) != 2 {
		t.Errorf("vulns len = %d, want 2", len(got.Results[0].Vulnerabilities))
	}
	if got.Results[0].Vulnerabilities[0].FixedVersion != "3.0.2-0ubuntu1.10" {
		t.Errorf("first FixedVersion = %q", got.Results[0].Vulnerabilities[0].FixedVersion)
	}
}

func TestBuildTrivyReport_MixedPackageManagerRejected(t *testing.T) {
	pkgs := []types.PatchPackage{
		{Name: "libssl3", TargetVersion: "3.0.2", PackageManager: "apt"},
		{Name: "openssl", TargetVersion: "3.0.2-r1", PackageManager: "apk"},
	}
	_, err := BuildTrivyReport("img:tag", "ubuntu", pkgs)
	if err == nil {
		t.Fatal("expected error for mixed packageManager")
	}
}

func TestBuildTrivyReport_EmptyPackagesRejected(t *testing.T) {
	_, err := BuildTrivyReport("img:tag", "ubuntu", nil)
	if err == nil {
		t.Fatal("expected error for empty packages")
	}
}

func TestBuildTrivyReport_MissingOSType(t *testing.T) {
	pkgs := []types.PatchPackage{{Name: "x", TargetVersion: "1"}}
	_, err := BuildTrivyReport("img:tag", "", pkgs)
	if err == nil {
		t.Fatal("expected error for missing osType")
	}
}

func TestOSTypeFromPackageManager(t *testing.T) {
	cases := map[string]string{
		"apt":      "ubuntu",
		"apk":      "alpine",
		"yum":      "centos",
		"dnf":      "fedora",
		"":         "",
		"unknown":  "",
	}
	for in, want := range cases {
		if got := OSTypeFromPackageManager(in); got != want {
			t.Errorf("OSTypeFromPackageManager(%q) = %q, want %q", in, got, want)
		}
	}
}
