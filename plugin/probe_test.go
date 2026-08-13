package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk/conformance"
)

// TestProbeBinary builds the plugin binary and probes it over the real
// HashiCorp go-plugin gRPC handshake, asserting the descriptor it serves
// matches the in-process module descriptor.
func TestProbeBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping plugin binary build")
	}
	binary := filepath.Join(t.TempDir(), "bomly-plugin-jsreach-analyzer")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/bomly-plugin-jsreach-analyzer")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOFLAGS=-modcacherw")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, out)
	}
	conformance.ProbeBinary(t, binary, conformance.WithModule(Module()))
}
