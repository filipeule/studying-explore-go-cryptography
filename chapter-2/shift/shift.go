package shift

func Encipher(plaintext []byte, key byte) ([]byte) {
	ciphertext := make([]byte, len(plaintext))

	for i, char := range plaintext {
		ciphertext[i] = char+key
	}

	return ciphertext
}