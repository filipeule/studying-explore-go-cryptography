package shift

func Encipher(plaintext []byte) ([]byte) {
	ciphertext := make([]byte, len(plaintext))

	for i, char := range plaintext {
		ciphertext[i] = char+1
	}

	return ciphertext
}