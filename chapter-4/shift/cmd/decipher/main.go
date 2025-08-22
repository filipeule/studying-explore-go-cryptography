package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/filipeule/shift"
)

func main() {
	key := flag.Int("key", 1, "unshift value")
	flag.Parse()

	ciphertext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plaintext := shift.Decipher(ciphertext, byte(*key))
	os.Stdout.Write(plaintext)
}