package patcher

import "testing"

func TestOSFromName(t *testing.T) {
	cases := map[string]string{
		"docker.io/library/ubuntu:22.04":        "ubuntu",
		"debian:bullseye":                       "debian",
		"alpine:3.18":                           "alpine",
		"quay.io/centos/centos:stream9":         "centos",
		"registry.access.redhat.com/ubi8":       "redhat",
		"public.ecr.aws/docker/library/fedora":  "fedora",
		"amazonlinux:2":                         "amazon",
		"container-registry.oracle.com/os/oraclelinux:8": "oracle",
		"rockylinux:9":                          "rocky",
		"almalinux:9":                           "almalinux",
		"mcr.microsoft.com/cbl-mariner/base/core:2.0": "cbl-mariner",
		"some/random/image:tag":                 "",
	}
	for ref, want := range cases {
		if got := osFromName(ref); got != want {
			t.Errorf("osFromName(%q) = %q, want %q", ref, got, want)
		}
	}
}
