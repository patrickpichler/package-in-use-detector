package tracer

import (
	"testing"
)

// Ensure that the algorithm used in eBPF and Go produce the same output.
func FuzzJHash(f *testing.F) {
	f.Add([]byte("cgroups"))
	f.Add([]byte("kubelet.slice"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		if len(data) > 255 {
			data = data[0:255]
		}

		want := jenkinsOneAtATimeC(data)
		got := jenkinsOneAtATime(data)
		if want != got {
			t.Errorf("jhash_optimized() = %v, want %v", got, want)
		}
	})
}
