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
	key := flag.String("key", "01", "key in hexadecimal (for example 'FF')")
	flag.Parse()

	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	decodedKey, err := hex.DecodeString(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ciphertext := shift.Encipher(plaintext, decodedKey)
	os.Stdout.Write(ciphertext)
}