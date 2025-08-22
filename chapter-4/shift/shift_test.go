package shift_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/filipeule/shift"
)

var cases = []struct {
		plaintext, ciphertext []byte
		key         byte
	}{
		{plaintext: []byte("HAL"), ciphertext: []byte("IBM"), key: 1},
		{plaintext: []byte("SPEC"), ciphertext: []byte("URGE"), key: 2},
		{plaintext: []byte("PERK"), ciphertext: []byte("SHUN"), key: 3},
		{plaintext: []byte("GEL"), ciphertext: []byte("KIP"), key: 4},
		{plaintext: []byte("CHEER"), ciphertext: []byte("JOLLY"), key: 7},
		{plaintext: []byte("BEEF"), ciphertext: []byte("LOOP"), key: 10},
	}

func TestEncipherTransforms(t *testing.T) {
	t.Parallel()

	for _, tc := range cases {
		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got := shift.Encipher(tc.plaintext, tc.key)
			if !bytes.Equal(tc.ciphertext, got) {
				t.Errorf("want %q, got %q", tc.ciphertext, got)
			}
		})
	}
}

func TestDecipherTransform(t *testing.T) {
	t.Parallel()

	for _, tc := range cases {
		name := fmt.Sprintf("%s - %d = %s", tc.ciphertext, tc.key, tc.plaintext)
		t.Run(name, func(t *testing.T) {
			got := shift.Decipher(tc.ciphertext, tc.key)
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("expected %q, got %q", tc.plaintext, got)
			}
		})
	}
}

func TestCrack(t *testing.T) {
	t.Parallel()

	for _, tc := range cases {
		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got, err := shift.Crack(tc.ciphertext, tc.plaintext[:3])
			if err != nil {
				t.Fatal(err)
			}
			if tc.key != got {
				t.Errorf("want %q, got %q", tc.key, got)
			}
		})
	}
}

func TestCrackReturnsErrorWhenKeyNotFound(t *testing.T) {
	t.Parallel()

	_, err := shift.Crack([]byte("no good"), []byte("bogus"))
	if err == nil {
		t.Fatal("want error when key not found, got nil")
	}
}