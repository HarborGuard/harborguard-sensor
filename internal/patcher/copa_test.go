package patcher

import "testing"

func TestRegistryHostFromRef(t *testing.T) {
	cases := map[string]string{
		"ubuntu:22.04":                               "docker.io",
		"docker.io/library/ubuntu:22.04":             "docker.io",
		"ghcr.io/harborguard/sensor:latest":          "ghcr.io",
		"quay.io/org/app":                            "quay.io",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1": "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"localhost:5000/myapp:dev":                   "localhost:5000",
		"registry.example.com:5000/org/app:latest":   "registry.example.com:5000",
	}
	for ref, want := range cases {
		if got := registryHostFromRef(ref); got != want {
			t.Errorf("registryHostFromRef(%q) = %q, want %q", ref, got, want)
		}
	}
}
