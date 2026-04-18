package sink

import "testing"

func TestResolveFullRef(t *testing.T) {
	cases := []struct {
		name      string
		sinkRef   string
		sourceRef string
		want      string
		wantErr   bool
	}{
		{
			name:      "bare ECR host synthesizes repo from source",
			sinkRef:   "572590828342.dkr.ecr.us-east-1.amazonaws.com",
			sourceRef: "572590828342.dkr.ecr.us-east-1.amazonaws.com/cloud-test/python:pw-testauth",
			want:      "572590828342.dkr.ecr.us-east-1.amazonaws.com/cloud-test/python",
		},
		{
			name:      "full sink ref is preserved",
			sinkRef:   "registry.example.com/myteam/myapp",
			sourceRef: "docker.io/library/alpine:3.18",
			want:      "registry.example.com/myteam/myapp",
		},
		{
			name:      "source with digest",
			sinkRef:   "ghcr.io",
			sourceRef: "ghcr.io/org/app:v1@sha256:abc123",
			want:      "ghcr.io/org/app",
		},
		{
			name:      "bare sink and bare source errors",
			sinkRef:   "registry.example.com",
			sourceRef: "alpine",
			wantErr:   true,
		},
		{
			name:    "empty sink ref errors",
			sinkRef: "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveFullRef(tc.sinkRef, tc.sourceRef)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ref=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
