package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
)

func TestGeneratedSnapshotImportsAndRefusesOverwrite(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "example")
	if err := generate(source); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(source, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := acquire.DecodePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(base, "bundle")
	if _, err := acquire.Docker(context.Background(), acquire.Options{Source: filepath.Join(source, "source"), Output: bundle, Plan: plan, Limits: custody.DefaultLimits()}); err != nil {
		t.Fatal(err)
	}
	c, err := casefile.Open(filepath.Join(bundle, "case"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity(); err != nil {
		t.Fatal(err)
	}
	if err := generate(source); err == nil {
		t.Fatal("existing example was replaced")
	}
	unchanged, err := os.ReadFile(filepath.Join(source, "plan.json"))
	if err != nil || string(unchanged) != string(data) {
		t.Fatal("existing plan changed")
	}
}
