package model

import "testing"

func sample() *Report {
	return &Report{
		Schema:      SchemaReport,
		Path:        "/usr/bin/helper",
		Verdict:     VerdictFromImageLayer,
		Explanation: "from image layer 1/1",
		Facts: []Fact{{
			ID:       "f1",
			Kind:     "layer_entry",
			Source:   Source{Artifact: "layer", Path: "host/l1/x"},
			Strength: Observed,
		}},
		Claims: []Claim{{
			Kind:      "visible_provider",
			Answer:    "layer:1",
			DependsOn: []string{"f1"},
			Strength:  Observed,
		}},
	}
}

func TestSealIsStable(t *testing.T) {
	r := sample()
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	first := r.SHA256
	if first == "" {
		t.Fatal("seal produced an empty digest")
	}

	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if r.SHA256 != first {
		t.Fatalf("re-sealing changed the digest: %s != %s", r.SHA256, first)
	}
}

func TestSealDetectsChange(t *testing.T) {
	r := sample()
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	first := r.SHA256

	r.Explanation = "something else"
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	if r.SHA256 == first {
		t.Fatal("seal did not change after the document changed")
	}
}

func TestHasAssumed(t *testing.T) {
	r := sample()
	if r.HasAssumed() {
		t.Fatal("observed claims must not be reported as assumed")
	}
	r.Claims[0].Strength = Assumed
	if !r.HasAssumed() {
		t.Fatal("an assumed claim must be detected")
	}
}
