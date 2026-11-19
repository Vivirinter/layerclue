package cli

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Vivirinter/layerclue/internal/evidence"
)

func TestWorkerOutputLimitSurvivesIOCopyFastPath(t *testing.T) {
	dst := &cappedBuffer{Max: 16}
	// Hide WriterTo on the source. An embedded bytes.Buffer would expose
	// ReaderFrom on the destination and bypass cappedBuffer.Write entirely.
	src := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 4096))}
	if _, err := io.Copy(dst, src); !errors.Is(err, evidence.ErrLimit) {
		t.Fatalf("io.Copy bypassed output limit: %v", err)
	}
	if dst.Len() > dst.Max {
		t.Fatal("buffer exceeded its maximum")
	}
}
