package registry

import "testing"

func TestNormalizeRegistryURL(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		insecure bool
		want     string
	}{
		{"bare host insecure → http", "host:5000", true, "http://host:5000"},
		{"bare host secure → https", "registry.example.com", false, "https://registry.example.com"},
		{"explicit https wins even when insecure", "https://host:5000", true, "https://host:5000"},
		{"explicit http preserved when secure", "http://host:5000", false, "http://host:5000"},
		{"trailing slash trimmed", "host:5000/", false, "https://host:5000"},
		{"trailing slash trimmed insecure", "host:5000/", true, "http://host:5000"},
		{"explicit https with trailing path", "https://host:5000/v2/", true, "https://host:5000/v2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeRegistryURL(c.raw, c.insecure)
			if got != c.want {
				t.Errorf("normalizeRegistryURL(%q, %t) = %q, want %q", c.raw, c.insecure, got, c.want)
			}
		})
	}
}
