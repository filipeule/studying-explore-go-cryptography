package shift_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/filipeule/shift"
)

func TestEncipherTransforms(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		input, want []byte
		key         byte
	}{
		{input: []byte("HAL"), want: []byte("IBM"), key: 1},
		{input: []byte("SPEC"), want: []byte("URGE"), key: 2},
		{input: []byte("PERK"), want: []byte("SHUN"), key: 3},
		{input: []byte("GEL"), want: []byte("KIP"), key: 4},
		{input: []byte("CHEER"), want: []byte("JOLLY"), key: 7},
		{input: []byte("BEEF"), want: []byte("LOOP"), key: 10},
	}

	for _, tc := range tcs {
		name := fmt.Sprintf("%s + %d = %s", tc.input, tc.key, tc.want)
		t.Run(name, func(t *testing.T) {
			got := shift.Encipher(tc.input, tc.key)
			if !bytes.Equal(tc.want, got) {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}
