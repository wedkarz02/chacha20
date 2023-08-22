package chacha20

import (
	"crypto/sha256"
	"errors"
)

const (
	BLOCK_SIZE = 64
	WORD_SIZE  = 4
	KEY_SIZE   = 32
)

// "expand 32-byte k"
const (
	CONSTANT_0 = uint32(0x61707865)
	CONSTANT_1 = uint32(0x3320646e)
	CONSTANT_2 = uint32(0x79622d32)
	CONSTANT_3 = uint32(0x6b206574)
)

var (
	ErrKeySize = errors.New("invalid key size")
)

type Cipher struct {
	Key []byte
}

func NewCipher(k []byte) (*Cipher, error) {
	hashedKey := newSHA256(k)

	if len(hashedKey) != KEY_SIZE {
		return nil, ErrKeySize
	}

	c := Cipher{Key: hashedKey}

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
