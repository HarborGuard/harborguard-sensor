package agent

import "testing"

func TestRefHostMatches(t *testing.T) {
	cases := []struct {
		name        string
		imageRef    string
		registryURL string
		want        bool
	}{
		{"bare host:port match", "host.docker.internal:5000/test/alpine:3.18", "host.docker.internal:5000", true},
		{"registry has scheme", "host.docker.internal:5000/test/alpine:3.18", "http://host.docker.internal:5000", true},
		{"image has scheme", "https://host.docker.internal:5000/test/alpine:3.18", "host.docker.internal:5000", true},
		{"different host", "ghcr.io/foo/bar:tag", "host.docker.internal:5000", false},
		{"case-insensitive", "HOST.docker.internal:5000/repo:tag", "host.docker.internal:5000", true},
		{"docker hub bare name does not match arbitrary registry", "alpine:3.18", "host.docker.internal:5000", false},
		{"empty image ref", "", "host.docker.internal:5000", false},
		{"trailing slash on registry url", "host:5000/repo:tag", "host:5000/", true},
		{"empty registry URL", "host:5000/repo:tag", "", false},
		{"both empty", "", "", false},
		{"docker hub bare with port-like tag, registry literally same string", "alpine:5000", "alpine:5000", true},
		{"docker hub bare ref vs unrelated registry", "alpine:5000", "host.docker.internal:5000", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := refHostMatches(c.imageRef, c.registryURL); got != c.want {
				t.Errorf("refHostMatches(%q, %q) = %t, want %t", c.imageRef, c.registryURL, got, c.want)
			}
		})
	}
}
