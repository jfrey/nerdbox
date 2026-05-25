//go:build !windows

package manager

import (
	"path/filepath"
	"testing"

	bootapi "github.com/containerd/containerd/api/runtime/bootstrap/v1"
	"github.com/containerd/containerd/v2/defaults"
)

func TestShimSocketDirPrefersBootstrapParam(t *testing.T) {
	t.Setenv("SHIM_SOCKET_DIR", "/tmp/env-shim")
	socketDir := "/tmp/bootstrap-shim"

	got := shimSocketDir(&bootapi.BootstrapParams{SocketDir: &socketDir})
	if got != socketDir {
		t.Fatalf("shimSocketDir() = %q, want %q", got, socketDir)
	}
}

func TestShimSocketDirUsesEnvironmentFallback(t *testing.T) {
	t.Setenv("SHIM_SOCKET_DIR", "/tmp/env-shim")

	got := shimSocketDir(&bootapi.BootstrapParams{})
	if got != "/tmp/env-shim" {
		t.Fatalf("shimSocketDir() = %q, want %q", got, "/tmp/env-shim")
	}
}

func TestShimSocketDirUsesContainerdDefault(t *testing.T) {
	t.Setenv("SHIM_SOCKET_DIR", "")

	got := shimSocketDir(&bootapi.BootstrapParams{})
	want := filepath.Join(defaults.DefaultStateDir, "s")
	if got != want {
		t.Fatalf("shimSocketDir() = %q, want %q", got, want)
	}
}
