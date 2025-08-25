package shift

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

// func Crack(ciphertext, crib []byte) (byte, error) {
// 	for guess := range 256 {
// 		res := Decipher(ciphertext[:len(crib)], byte(guess))

// 		if bytes.Equal(res, crib) {
// 			return byte(guess), nil
// 		}
// 	}

// 	return 0, errors.New("key not found")
// }
