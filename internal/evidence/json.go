package evidence

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeJSON rejects duplicate keys, trailing documents and excessive nesting.
// Silently keeping the last duplicate value is unsuitable for evidence.
func DecodeJSON(data []byte, dst any) error {
	return decodeJSON(data, dst, false, 200000)
}

// DecodeExtensibleJSON retains duplicate/depth checks but permits the
// extension fields allowed by OCI. It never interprets unknown fields as paths.
func DecodeExtensibleJSON(data []byte, dst any) error { return decodeJSON(data, dst, true, 200000) }

// DecodeInventoryJSON retains strict fields, duplicate-key and depth checks.
// Larger byte-bounded inventories need more scalar values than small control
// manifests. The caller must bound bytes before calling this function.
func DecodeInventoryJSON(data []byte, dst any) error {
	if len(data) > 16<<20 {
		return ErrLimit
	}
	return decodeJSON(data, dst, false, 1000000)
}

func decodeJSON(data []byte, dst any, extensible bool, maxValues int) error {
	if !utf8.Valid(data) {
		return errors.New("JSON is not valid UTF-8")
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	count := 0
	var value func(int) error
	value = func(depth int) error {
		count++
		if depth > 64 || count > maxValues {
			return ErrLimit
		}
		t, err := tokens.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for tokens.More() {
				key, err := tokens.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if seen[name] {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for tokens.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = tokens.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("expected one JSON document")
	}
	// Preserve v1 wire/number semantics, but reject duplicate destinations as
	// well as duplicate spellings ("schema" and "SCHEMA" bind the same field).
	// The standard v2 decoder also refuses lossy UTF-16 surrogate replacement.
	return jsonv2.Unmarshal(data, dst,
		json.DefaultOptionsV1(),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
		jsonv2.RejectUnknownMembers(!extensible),
		jsonv2.WithUnmarshalers(rawNumbers),
	)
}

// Reports hash arbitrary fact values. Retain exact numeric literals rather
// than rounding integers through float64. UnmarshalFunc receives a syntactically
// validated JSON value, so this does not bypass the v2 duplicate/Unicode checks.
var rawNumbers = jsonv2.UnmarshalFunc(func(data []byte, dst *any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(dst)
})
