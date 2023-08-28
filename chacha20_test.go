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

package chacha20

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/wedkarz02/chacha20/util"
)

func printState(state [16]uint32) {
	for i, num := range state {
		if i%4 == 0 {
			fmt.Println()
		}

		fmt.Printf("%08x ", num)
	}
	fmt.Println()
}

func printBytes(bytes []byte) {
	for i, b := range bytes {
		if i%16 == 0 {
			fmt.Println()
		}

		if i%4 == 0 && i%16 != 0 {
			fmt.Print(" ")
		}

		fmt.Printf("%02x", b)
	}
	fmt.Println()
}

func TestNewNonce(t *testing.T) {
	n, err := util.NewNonce()
	if err != nil {
		panic(err)
	}

	printBytes(n.Bytes[:])
}

func TestNewCipher(t *testing.T) {
	c, err := NewCipher([]byte("asdf"))
	if err != nil {
		panic(err)
	}

	printState(c.state)
}

func TestQuarterRound(t *testing.T) {
	testStateVectors := []struct {
		startingState [16]uint32
		expectedState [16]uint32
	}{
		{
			startingState: [16]uint32{
				0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
				0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
				0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
				0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
			},
			expectedState: [16]uint32{
				0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
				0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
				0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
				0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
			},
		},
	}

	c, err := NewCipher([]byte("doesnt matter what goes here"))
	if err != nil {
		panic(err)
	}

	c.state = testStateVectors[0].startingState
	c.quarterRound(2, 7, 8, 13)

	for i, num := range c.state {
		if !reflect.DeepEqual(num, testStateVectors[0].expectedState[i]) {
			t.Fatalf("FAIL: quarterround failed")
		}
	}
}

func TestBlock(t *testing.T) {
	testVectors := []struct {
		startingState [16]uint32
		expectedState [16]uint32
	}{
		{
			startingState: [16]uint32{
				0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
				0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
				0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
				0x00000001, 0x09000000, 0x4a000000, 0x00000000,
			},
			expectedState: [16]uint32{
				0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
				0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
				0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
				0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
			},
		},
	}

	c, err := NewCipher([]byte("doesnt matter what goes here"))
	if err != nil {
		panic(err)
	}

	c.state = testVectors[0].startingState
	c.ctr = c.state[12]

	c.block()

	for i, num := range c.state {
		if !reflect.DeepEqual(num, testVectors[0].expectedState[i]) {
			t.Fatalf("FAIL: block failed")
		}
	}
}

func TestEncrypt(t *testing.T) {
	testVectors := []struct {
		key                []byte
		nonce              []byte
		plainText          []byte
		expectedCipherText []byte
	}{
		{
			key: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			nonce: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
			},
			plainText: []byte{
				0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
				0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
				0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
				0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
				0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
				0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
				0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
				0x74, 0x2e,
			},
			expectedCipherText: []byte{
				0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
				0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
				0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
				0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
				0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
				0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
				0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
				0x87, 0x4d,
			},
		},
	}

	c, err := NewCipher([]byte("doesnt matter what goes here"))
	if err != nil {
		panic(err)
	}

	c.Key = testVectors[0].key
	c.nonce.Bytes = [12]byte(testVectors[0].nonce)
	c.resetState()

	actualCipherText, err := c.Encrypt(testVectors[0].plainText)
	if err != nil {
		panic(err)
	}

	for i, b := range testVectors[0].expectedCipherText {
		if !reflect.DeepEqual(b, actualCipherText[i]) {
			t.Fatalf("encryption failed at index %d: expected %02x, found %02x", i, testVectors[0].expectedCipherText[i], b)
		}
	}

	fmt.Println(string(actualCipherText))
}

func TestDecrypt(t *testing.T) {
	testVectors := []struct {
		key               []byte
		nonce             []byte
		cipherText        []byte
		expectedPlainText []byte
	}{
		{
			key: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			nonce: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
			},
			cipherText: []byte{
				0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
				0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
				0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
				0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
				0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
				0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
				0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
				0x87, 0x4d,
			},
			expectedPlainText: []byte{
				0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
				0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
				0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
				0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
				0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
				0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
				0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
				0x74, 0x2e,
			},
		},
	}

	c, err := NewCipher([]byte("doesnt matter what goes here"))
	if err != nil {
		panic(err)
	}

	c.Key = testVectors[0].key
	c.nonce.Bytes = [12]byte(testVectors[0].nonce)
	c.resetState()

	actualPlainText, err := c.Encrypt(testVectors[0].cipherText)
	if err != nil {
		panic(err)
	}

	for i, b := range testVectors[0].expectedPlainText {
		if !reflect.DeepEqual(b, actualPlainText[i]) {
			t.Fatalf("encryption failed at index %d: expected %02x, found %02x", i, testVectors[0].expectedPlainText[i], b)
		}
	}

	fmt.Println(string(actualPlainText))
}
