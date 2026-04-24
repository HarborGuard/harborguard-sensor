package config

import "testing"

func TestParseTruthy(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "True", "yes", "YES", "on", "ON", "  true  "}
	for _, v := range truthy {
		if !parseTruthy(v) {
			t.Errorf("parseTruthy(%q) = false, want true", v)
		}
	}
	falsy := []string{"", "0", "false", "no", "off", "anything-else"}
	for _, v := range falsy {
		if parseTruthy(v) {
			t.Errorf("parseTruthy(%q) = true, want false", v)
		}
	}
}
