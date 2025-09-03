package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/filipeule/shift"
)

func main() {
	crib := flag.String("crib", "", "crib for crack the ciphertext")
	flag.Parse()

	if *crib == "" {
		fmt.Fprintln(os.Stderr, "please provide a crib text with -crib")
		os.Exit(1)
	}

	ciphertext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	key, err := shift.Crack(ciphertext, []byte(*crib))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting key to decipher: %v", err)
		os.Exit(1)
	}

	block, err := shift.NewCipher(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mode := shift.NewDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext = shift.Unpad(plaintext, mode.BlockSize())
	os.Stdout.Write(plaintext)
}