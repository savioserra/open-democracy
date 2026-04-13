package tui

import "testing"

func TestNormalizeGatewayPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default on empty", input: "", want: "8080"},
		{name: "trim whitespace", input: " 8080 ", want: "8080"},
		{name: "canonicalize numeric", input: "08080", want: "8080"},
		{name: "reject letters", input: "8080J", wantErr: true},
		{name: "reject zero", input: "0", wantErr: true},
		{name: "reject too large", input: "65536", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeGatewayPort(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeGatewayPort(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
