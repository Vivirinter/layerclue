// Package render writes reports for humans and for machines.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, rep *model.Report) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(b)) > evidence.MaxReportBytes {
		return evidence.ErrLimit
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// Terminal writes the human answer: verdict first, evidence after.
func Terminal(w io.Writer, rep *model.Report, showTrace bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n\n", Safe(rep.Path))

	if rep.ContainerID != "" {
		fmt.Fprintf(&b, "  %-10s %s\n", "container", Safe(rep.ContainerID))
	}
	if rep.ImageRef != "" {
		label := rep.ImageRef
		if rep.ImageDigest != "" {
			label += "  " + shortDigest(rep.ImageDigest)
		}
		fmt.Fprintf(&b, "  %-10s %s\n", "image ref", Safe(label))
	}
	if rep.PodName != "" {
		fmt.Fprintf(&b, "  %-10s %s/%s\n", "pod", Safe(rep.PodNamespace), Safe(rep.PodName))
	}
	if rep.ContainerID != "" || rep.ImageRef != "" || rep.PodName != "" {
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "  %-10s %s\n", "verdict", Safe(string(rep.Verdict)))
	fmt.Fprintf(&b, "  %-10s %s\n", "visible", describeView(rep.Visible, rep.VisibleState))
	fmt.Fprintf(&b, "  %-10s %s\n", "lower view", describeView(rep.Image, rep.LowerState))
	fmt.Fprintf(&b, "  %-10s %s\n", "strength", strengthOf(rep))
	if proof := rep.ImageProvenance; proof != nil {
		fmt.Fprintf(&b, "  %-10s %s\n", "image link", Safe(proof.Status))
		fmt.Fprintf(&b, "  %-10s %s\n", "manifest", Safe(proof.ManifestDigest))
		fmt.Fprintf(&b, "  %-10s %s\n", "scope", Safe(proof.Scope))
		if proof.Error != "" {
			fmt.Fprintf(&b, "  %-10s %s\n", "proof error", Safe(proof.Error))
		}
	}
	fmt.Fprintf(&b, "\n  %s\n", Safe(rep.Explanation))

	if len(rep.Missing) > 0 {
		fmt.Fprintf(&b, "\n  missing evidence:\n")
		for _, m := range rep.Missing {
			fmt.Fprintf(&b, "    - %s\n", Safe(m))
		}
	}

	if showTrace {
		fmt.Fprintf(&b, "\n  trace:\n")
		for i, s := range rep.Trace {
			fmt.Fprintf(&b, "    %2d. %-7s %-16s %s", i+1, Safe(s.View), Safe(string(s.Kind)), Safe(s.Path))
			if s.Detail != "" {
				fmt.Fprintf(&b, "  [%s]", Safe(s.Detail))
			}
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n  facts:\n")
		for _, f := range rep.Facts {
			fmt.Fprintf(&b, "    %-4s %-18s %s", Safe(f.ID), Safe(f.Kind), Safe(f.Source.Artifact))
			if f.Source.Line > 0 {
				fmt.Fprintf(&b, ":%d", f.Source.Line)
			}
			if f.Source.Path != "" {
				fmt.Fprintf(&b, " %s", Safe(f.Source.Path))
			}
			b.WriteByte('\n')
		}
	}

	if rep.SHA256 != "" {
		fmt.Fprintf(&b, "\n  report_sha256 %s\n", Safe(rep.SHA256))
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func describeOr(l *model.Location, fallback string) string {
	if l == nil {
		return fallback
	}
	var b strings.Builder
	if l.Provider == "mount" {
		fmt.Fprintf(&b, "mount %s (source %s)", Safe(l.MountPoint), Safe(l.MountSource))
	} else {
		fmt.Fprintf(&b, "layer %d/%d", l.LayerIndex+1, l.LayerTotal)
		if l.LayerDigest != "" {
			fmt.Fprintf(&b, " (metadata OCI %s)", Safe(l.LayerDigest))
		}
	}
	fmt.Fprintf(&b, "  %s", Safe(l.Type))
	if l.SHA256 != "" {
		fmt.Fprintf(&b, "  sha256:%s", Safe(shortDigest(l.SHA256)))
	}
	if l.LinkTarget != "" {
		fmt.Fprintf(&b, "  -> %s", Safe(l.LinkTarget))
	}
	if l.MetaCopy {
		b.WriteString("  metacopy")
	}
	return b.String()
}

func describeView(l *model.Location, state model.PathState) string {
	switch state {
	case model.PathAbsent:
		return "absent in captured view (prior existence unknown)"
	case model.PathWhiteout:
		return "blocked by a captured whiteout (prior existence unknown)"
	case model.PathOpaque:
		return "hidden by a captured opaque directory"
	case model.PathUnknown:
		return "unknown (insufficient evidence)"
	default:
		// A nil v3 location never proves absence.
		return describeOr(l, "unknown (state not recorded)")
	}
}

func strengthOf(rep *model.Report) model.Strength {
	if !rep.Complete() || len(rep.Claims) == 0 {
		return model.Unknown
	}
	for _, claim := range rep.Claims {
		if claim.Strength == model.Derived {
			return model.Derived
		}
	}
	return model.Observed
}

// Safe escapes control and format characters before displaying artifact data.
func Safe(s string) string {
	quoted := strconv.QuoteToGraphic(s)
	return quoted[1 : len(quoted)-1]
}

func shortDigest(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}
