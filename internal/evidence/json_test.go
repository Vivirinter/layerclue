package evidence

import (
	"strings"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{} {}`, `{"other":1}`, strings.Repeat("[", 65) + strings.Repeat("]", 65)} {
		var dst struct {
			A int `json:"a"`
		}
		if err := DecodeJSON([]byte(input), &dst); err == nil {
			t.Fatalf("accepted ambiguous JSON %s", input)
		}
	}
}

func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"a":1,"A":2}`))
	f.Add([]byte(`{"a":"\ud800"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var dst any
		_ = DecodeJSON(data, &dst)
		var typed struct {
			A any `json:"a"`
		}
		_ = DecodeJSON(data, &typed)
	})
}
