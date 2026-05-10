package proxy

import (
	"bytes"
	"encoding/json"
)

// newJSONDecoder centralises decoder construction so tests + http.go +
// stdio.go all share the same flags (UseNumber off; structured errors).
func newJSONDecoder(b []byte) *json.Decoder {
	return json.NewDecoder(bytes.NewReader(b))
}
