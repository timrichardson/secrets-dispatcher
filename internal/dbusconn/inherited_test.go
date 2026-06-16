package dbusconn

import "testing"

func TestInheritedFDFromEnv(t *testing.T) {
	t.Setenv(BackendFDEnv, "7")
	fd, err := inheritedFDFromEnv()
	if err != nil {
		t.Fatalf("inheritedFDFromEnv() error: %v", err)
	}
	if fd != 7 {
		t.Fatalf("inheritedFDFromEnv() = %d, want 7", fd)
	}
}

func TestInheritedFDFromEnvMissing(t *testing.T) {
	t.Setenv(BackendFDEnv, "")
	if _, err := inheritedFDFromEnv(); err == nil {
		t.Fatal("inheritedFDFromEnv() error = nil, want missing-env error")
	}
}

func TestInheritedFDFromEnvInvalid(t *testing.T) {
	t.Setenv(BackendFDEnv, "not-a-fd")
	if _, err := inheritedFDFromEnv(); err == nil {
		t.Fatal("inheritedFDFromEnv() error = nil, want invalid-env error")
	}
}
