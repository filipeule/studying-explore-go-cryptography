package shift_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/filipeule/shift"
)

var testKey = bytes.Repeat([]byte{1}, shift.BlockSize)

var cipherCases = []struct{
	plaintext, ciphertext []byte
}{
	{
		plaintext: []byte{0, 1, 2, 3, 4, 5},
		ciphertext: []byte{1, 2, 3, 4, 5, 6},
	},
}

func TestNewCipher_GivesNoErrorWithValidKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, shift.BlockSize)

	_, err := shift.NewCipher(key)
	if err != nil {
		t.Errorf("expected no error, got '%v'", err)
	}
}

func TestNewCipher_GivesErrorWithInvalidKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, 10)

	_, err := shift.NewCipher(key)
	if err == nil {
		t.Errorf("expected some error, got nil")
	}
}

func TestNewCipher_GivesErrKeySizeWithInvalidKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, 10)

	_, err := shift.NewCipher(key)
	if !errors.Is(err, shift.ErrKeySize) {
		t.Errorf("expected ErrKeySize, got %v", err)
	}
}


func TestEncrypt(t *testing.T) {
	t.Parallel()

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cipherCases {
		name := fmt.Sprintf("%x + %x = %x", tc.plaintext, testKey, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got := make([]byte, len(tc.plaintext))
			block.Encrypt(got, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, got) {
				t.Errorf("expected %x, got %x", tc.ciphertext, got)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	t.Parallel()

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cipherCases {
		name := fmt.Sprintf("%x - %x = %x", tc.plaintext, testKey, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got := make([]byte, len(tc.plaintext))
			block.Decrypt(got, tc.ciphertext)
			if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("expected %x, got %x", tc.plaintext, got)
			}
		})
	}
}

func TestBlockSize_ReturnsBlockSize(t *testing.T) {
	t.Parallel()

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	want := shift.BlockSize
	got := block.BlockSize()
	if want != got {
		t.Errorf("expected %d, got %d", want, got)
	}
}

// func TestCrack(t *testing.T) {
// 	t.Parallel()

// 	for _, tc := range cases {
// 		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
// 		t.Run(name, func(t *testing.T) {
// 			got, err := shift.Crack(tc.ciphertext, tc.plaintext[:3])
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			if !bytes.Equal(tc.key, got) {
// 				t.Errorf("want %d, got %d", tc.key, got)
// 			}
// 		})
// 	}
// }