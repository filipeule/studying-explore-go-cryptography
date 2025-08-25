package shift_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/filipeule/shift"
)

var cases = []struct {
	plaintext  []byte
	ciphertext []byte
	key        []byte
}{
	{
		plaintext:  []byte("HAL"),
		ciphertext: []byte("IBM"),
		key:        []byte{1},
	},
	{
		plaintext:  []byte{0, 0, 0},
		ciphertext: []byte{1, 2, 3},
		key:        []byte{1, 2, 3},
	},
	{
		plaintext:  []byte{0, 1, 2},
		ciphertext: []byte{1, 3, 3},
		key:        []byte{1, 2},
	},
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
			if !bytes.Equal(tc.key, got) {
				t.Errorf("want %d, got %d", tc.key, got)
			}
		})
	}
}