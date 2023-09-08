// Copyright (c) 2023 Paweł Rybak
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package examples contains code guides and should not be imported.
package examples

import (
	"log"

	"github.com/wedkarz02/chacha20"
)

// This is an example usage of ChaCha20 encryption.
func EncryptExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := chacha20.NewCipher(key)

	// It is strongly recommended to wipe the key from memory at the end.
	defer cipher.ClearKey()

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText.
	cipherText, err := cipher.Encrypt(plainText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of ChaCha20 decryption.
func DecryptExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := chacha20.NewCipher(key)

	// It is strongly recommended to wipe the key from memory at the end.
	defer cipher.ClearKey()

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText.
	plainText, err := cipher.Decrypt(cipherText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainText
}
