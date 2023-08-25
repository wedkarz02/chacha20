// Copyright (c) 2023 Paweł Rybak

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package chacha20 implements the ChaCha20 encryption algorithm.
package chacha20

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/wedkarz02/chacha20/util"
)

const (
	// Size of the ChaCha20 state in uint32 words.
	STATE_SIZE = 16

	// Size of the key in bytes.
	KEY_SIZE = 32

	// Size of the nonce in the 96-bit variant.
	NONCE_SIZE = util.NONCE_SIZE

	// Number of ChaCha rounds
	NR = 20
)

const (
	// ChaCha constant: "expa"
	CONSTANT_0 = uint32(0x61707865)

	// ChaCha constant: "nd 3"
	CONSTANT_1 = uint32(0x3320646e)

	// ChaCha constant: "2-by"
	CONSTANT_2 = uint32(0x79622d32)

	// ChaCha constant: "te k"
	CONSTANT_3 = uint32(0x6b206574)
)

var (
	// Error returned if the key is not 32 bytes.
	ErrKeySize = errors.New("invalid key size")
)

// Cipher structure contains information about the key,
// the state, current counter number and the nonce.
type Cipher struct {
	Key   []byte
	state [STATE_SIZE]uint32
	ctr   uint32
	nonce *util.Nonce
}

func NewCipher(k []byte) (*Cipher, error) {
	hashedKey := newSHA256(k)

	if len(hashedKey) != KEY_SIZE {
		return nil, ErrKeySize
	}

	n, err := util.NewNonce()
	if err != nil {
		return nil, err
	}

	c := Cipher{
		Key:   hashedKey,
		ctr:   uint32(0),
		nonce: n,
	}

	c.resetState()

	return &c, nil
}

func (c *Cipher) ClearKey() {
	for i := range c.Key {
		c.Key[i] = 0x00
	}
}

func newSHA256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

func (c *Cipher) resetState() {
	// Constants
	c.state[0] = CONSTANT_0
	c.state[1] = CONSTANT_1
	c.state[2] = CONSTANT_2
	c.state[3] = CONSTANT_3

	// Key
	for i := 0; i < 8; i++ {
		c.state[i+4] = binary.LittleEndian.Uint32(c.Key[i*4 : (i+1)*4])
	}

	// Counter
	c.state[12] = c.ctr

	// Nonce
	c.state[13] = binary.LittleEndian.Uint32(c.nonce.Bytes[0*4 : 1*4])
	c.state[14] = binary.LittleEndian.Uint32(c.nonce.Bytes[1*4 : 2*4])
	c.state[15] = binary.LittleEndian.Uint32(c.nonce.Bytes[2*4 : 3*4])
}

func (c *Cipher) CtrIncrement() {
	c.ctr++
	c.state[12] = c.ctr
}

func (c *Cipher) quarterRound(x, y, z, w int) {
	c.state[x] += c.state[y]
	c.state[w] ^= c.state[x]
	c.state[w] = bits.RotateLeft32(c.state[w], 16)
	c.state[z] += c.state[w]
	c.state[y] ^= c.state[z]
	c.state[y] = bits.RotateLeft32(c.state[y], 12)
	c.state[x] += c.state[y]
	c.state[w] ^= c.state[x]
	c.state[w] = bits.RotateLeft32(c.state[w], 8)
	c.state[z] += c.state[w]
	c.state[y] ^= c.state[z]
	c.state[y] = bits.RotateLeft32(c.state[y], 7)
}

func (c *Cipher) block() {
	var initialState [STATE_SIZE]uint32
	copy(initialState[:], c.state[:])

	// 20 rounds of alternating column rounds and diagonal rounds.
	for i := 0; i < NR/2; i++ {
		// Column round
		c.quarterRound(0, 4, 8, 12)
		c.quarterRound(1, 5, 9, 13)
		c.quarterRound(2, 6, 10, 14)
		c.quarterRound(3, 7, 11, 15)

		// Diagonal round
		c.quarterRound(0, 5, 10, 15)
		c.quarterRound(1, 6, 11, 12)
		c.quarterRound(2, 7, 8, 13)
		c.quarterRound(3, 4, 9, 14)
	}

	// Adding the initial state using mod 2^32 addition.
	for i, word := range initialState {
		c.state[i] += word
	}
}
