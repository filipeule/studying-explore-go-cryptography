package shift

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

const MaxKeyLength = 32
const BlockSize = 32

var (
	ErrKeySize = errors.New("shift: invalid key size")
)

type shiftCipher struct {
	key [BlockSize]byte
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, fmt.Errorf("%w %d (must be %d)", ErrKeySize, len(key), BlockSize)
	}

	return &shiftCipher{
		key: [BlockSize]byte(key),
	}, nil
}

func (sc *shiftCipher) Encrypt(dst, src []byte) {
	for i, char := range src {
		dst[i] = char + sc.key[i]
	}
}

func (sc *shiftCipher) Decrypt(dst, src []byte) {
	for i, char := range src {
		dst[i] = char - sc.key[i]
	}
}

func (sc *shiftCipher) BlockSize() int {
	return BlockSize
}

// func Crack(ciphertext, crib []byte) (key []byte, err error) {
// 	for k := range min(MaxKeyLength, len(ciphertext)) {
// 		for guess := range 256 {
// 			res := ciphertext[k] - byte(guess)
// 			if res == crib[k] {
// 				key = append(key, byte(guess))
// 				break
// 			}
// 		}

// 		if bytes.Equal(crib, Decipher(ciphertext[:len(crib)], key)) {
// 			return key, nil
// 		}
// 	}

// 	return nil, errors.New("key not found")
// }
