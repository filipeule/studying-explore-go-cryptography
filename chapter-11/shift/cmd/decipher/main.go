package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/filipeule/shift"
)

func main() {
	key := flag.String("key", "01", "32 bytes key in hexadecimal")
	flag.Parse()

	decodedKey, err := hex.DecodeString(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	block, err := shift.NewCipher(decodedKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ciphertext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plaintext := make([]byte, len(ciphertext))

	dec := shift.NewDecrypter(block)
	dec.CryptBlocks(plaintext, ciphertext)

	plaintext = shift.Unpad(plaintext, shift.BlockSize)
	os.Stdout.Write(plaintext)
}
