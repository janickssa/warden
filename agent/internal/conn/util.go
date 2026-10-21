package conn

import (
	"bytes"
	"encoding/json"

	"github.com/janickssa/warden/agent/internal/policy"
)

// runnerResolver follows symlinks on the real filesystem (README 7A).
var runnerResolver policy.Resolver = policy.RealResolver{}

// strictUnmarshal refuses unknown fields.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
