package analysis

import (
	"context"

	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/model"
	"github.com/Vivirinter/layerclue/internal/oci"
)

// Comparison describes selected file bytes and the captured report.
type Comparison struct {
	Schema         string        `json:"schema"`
	ManifestDigest string        `json:"manifest_digest"`
	Scope          string        `json:"scope"`
	Status         string        `json:"status"`
	Image          *oci.File     `json:"image"`
	Captured       *model.Report `json:"captured_report"`
}

// Compare checks captured file bytes against one explicitly selected OCI image.
func Compare(ctx context.Context, c *casefile.Case, target, contentRoot, manifest string, options Options) (*Comparison, error) {
	captured, err := BuildReport(ctx, c, target, options)
	if err != nil {
		return nil, err
	}
	image, err := oci.SelectFile(ctx, c.Root, contentRoot, manifest, target, oci.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if err := captured.Seal(); err != nil {
		return nil, err
	}
	out := Comparison{Schema: "layerclue.comparison/v1", ManifestDigest: manifest, Scope: "selected regular-file type and bytes in captured namespace versus explicitly selected OCI image; ownership, permissions, xattrs, execution history, original launch image and publisher authenticity are not verified", Image: image, Captured: captured, Status: "inconclusive"}
	if captured.Complete() {
		if image.Status == "present" && image.Kind == "file" && captured.Visible != nil && captured.Visible.Type == "file" && captured.Visible.SHA256 != "" {
			out.Status = "different_bytes"
			if captured.Visible.SHA256 == image.SHA256 {
				out.Status = "matching_bytes"
			}
		} else if image.Status == "absent" && captured.Visible != nil {
			out.Status = "absent_in_image"
		} else if image.Status == "present" && captured.Visible == nil {
			out.Status = "absent_in_capture"
		} else if image.Status == "absent" && captured.Visible == nil {
			out.Status = "both_absent"
		} else {
			out.Status = "not_regular_file"
		}
	}
	return &out, nil
}
