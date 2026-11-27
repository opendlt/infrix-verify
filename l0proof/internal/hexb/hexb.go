// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package hexb is the one byte-string type every l0proof structure uses on the wire: lower-case hex in JSON, so a fixture can be read and diffed by eye.
package hexb

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Bytes is a byte string that encodes as a JSON hex string. The decoder accepts upper or lower case and refuses anything else by name.
type Bytes []byte

// MarshalJSON encodes the bytes as lower-case hex.
func (b Bytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(b)) }

// UnmarshalJSON decodes a JSON hex string.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("a byte string must be a JSON hex string: %w", err)
	}
	v, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("a byte string must be hex: %w", err)
	}
	*b = v
	return nil
}
