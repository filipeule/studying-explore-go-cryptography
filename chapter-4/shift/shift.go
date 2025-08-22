package shift

import (
	"bytes"
	"errors"
)

func Encipher(plaintext []byte, key byte) []byte {
	ciphertext := make([]byte, len(plaintext))

	for i, char := range plaintext {
		ciphertext[i] = char + key
	}

	return ciphertext
}

func Decipher(message []byte, key byte) []byte {
	return Encipher(message, -key)
}

func Crack(ciphertext, crib []byte) (byte, error) {
	for guess := range 256 {
		res := Decipher(ciphertext[:len(crib)], byte(guess))

		if bytes.Equal(res, crib) {
			return byte(guess), nil
		}
	}

	return 0, errors.New("key not found")
}
