package evidence

import (
	"encoding/json"
	"testing"
)

func TestJSONRejectsCaseAliases(t *testing.T) {
	type descriptor struct {
		Digest string `json:"digest"`
	}
	type document struct {
		Schema string            `json:"schema"`
		Config descriptor        `json:"config"`
		Labels map[string]string `json:"labels"`
	}
	for _, input := range []string{
		`{"schema":"expected","SCHEMA":"other"}`,
		`{"config":{"digest":"expected","Digest":"other"}}`,
		`{"schema":"expected","\u017fchema":"other"}`,
	} {
		for _, extensible := range []bool{false, true} {
			var dst document
			var err error
			if extensible {
				err = DecodeExtensibleJSON([]byte(input), &dst)
			} else {
				err = DecodeJSON([]byte(input), &dst)
			}
			if err == nil {
				t.Errorf("accepted struct-field alias (extensible=%v): %s", extensible, input)
			}
		}
	}
	var dst document
	if err := DecodeExtensibleJSON([]byte(`{"schema":"expected","labels":{"Key":"one","key":"two"},"vendor":{"Schema":"extension"}}`), &dst); err != nil {
		t.Fatalf("case-sensitive map/unknown extension keys must remain valid: %v", err)
	}
	if dst.Labels["Key"] != "one" || dst.Labels["key"] != "two" {
		t.Fatal("map key spelling was changed")
	}
}

func TestJSONRejectsLossyUnicodeEscapes(t *testing.T) {
	for _, input := range []string{`{"path":"/\ud800"}`, `{"path":"/\udfff"}`, `{"\ud800":"value"}`, `{"path":"\ud800\u0041"}`} {
		var dst any
		if err := DecodeJSON([]byte(input), &dst); err == nil {
			t.Errorf("accepted an unpaired surrogate: %s", input)
		}
	}
	for _, input := range []string{`{"path":"/\ud83d\udd0d"}`, `{"path":"/\\ud800"}`, `{"path":"/�"}`} {
		var dst any
		if err := DecodeJSON([]byte(input), &dst); err != nil {
			t.Errorf("rejected valid Unicode or literal backslash: %s: %v", input, err)
		}
	}
}

func TestJSONPreservesExactNumbersAndPromotedFields(t *testing.T) {
	type descriptor struct {
		Digest string `json:"digest"`
	}
	var dst struct {
		descriptor
		Values map[string]any `json:"values"`
	}
	input := []byte(`{"digest":"expected","values":{"large":9007199254740993,"exponent":1.25e+100,"nested":[9223372036854775807]}}`)
	if err := DecodeJSON(input, &dst); err != nil {
		t.Fatal(err)
	}
	if dst.Digest != "expected" || dst.Values["large"] != json.Number("9007199254740993") || dst.Values["exponent"] != json.Number("1.25e+100") || dst.Values["nested"].([]any)[0] != json.Number("9223372036854775807") {
		t.Fatalf("promoted fields or numeric precision changed: %#v", dst)
	}
	if err := DecodeExtensibleJSON([]byte(`{"digest":"one","DIGEST":"two"}`), &dst); err == nil {
		t.Fatal("accepted a case alias for a promoted field")
	}
}
