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

	enc := shift.NewEncrypter(block)

	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plaintext = shift.Pad(plaintext, enc.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	enc.CryptBlocks(ciphertext, plaintext)
	os.Stdout.Write(ciphertext)
}