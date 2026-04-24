package scanner

import "testing"

func TestNormalizeImageRef(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantRef    string
		wantInsec  bool
		wantChange bool
	}{
		{"bare", "host:5000/repo:tag", "host:5000/repo:tag", false, false},
		{"http", "http://host:5000/repo:tag", "host:5000/repo:tag", true, true},
		{"https", "https://host.example.com/repo:tag", "host.example.com/repo:tag", false, true},
		{"empty", "", "", false, false},
		{"docker-daemon-ref", "alpine:3.18", "alpine:3.18", false, false},
		{"docker-transport-untouched", "docker://alpine:3.18", "docker://alpine:3.18", false, false},
		{"digest", "host/repo@sha256:abc", "host/repo@sha256:abc", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, insec, changed := NormalizeImageRef(c.in)
			if got != c.wantRef {
				t.Errorf("ref: got %q, want %q", got, c.wantRef)
			}
			if insec != c.wantInsec {
				t.Errorf("insecure: got %t, want %t", insec, c.wantInsec)
			}
			if changed != c.wantChange {
				t.Errorf("changed: got %t, want %t", changed, c.wantChange)
			}
		})
	}
}
