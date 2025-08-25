package shift

import (
	"bytes"
	"errors"
)

const MaxKeyLength = 32

func Encipher(plaintext []byte, key []byte) []byte {
	ciphertext := make([]byte, len(plaintext))

	for i, char := range plaintext {
		ciphertext[i] = char + key[i%len(key)]
	}

	return ciphertext
}

func Decipher(message []byte, key []byte) []byte {
	plaintext := make([]byte, len(message))

	for i, char := range message {
		plaintext[i] = char - key[i%len(key)]
	}

	return plaintext
}

func Crack(ciphertext, crib []byte) (key []byte, err error) {
	for k := range min(MaxKeyLength, len(ciphertext)) {
		for guess := range 256 {
			res := ciphertext[k] - byte(guess)
			if res == crib[k] {
				key = append(key, byte(guess))
				break
			}
		}

		if bytes.Equal(crib, Decipher(ciphertext[:len(crib)], key)) {
			return key, nil
		}
	}

	return nil, errors.New("key not found")
}
