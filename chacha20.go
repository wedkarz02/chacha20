package chacha20

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/wedkarz02/chacha20/util"
)

const (
	STATE_SIZE = 16 // uint32
	// WORD_SIZE    = 4
	KEY_SIZE   = 32              // byte
	NONCE_SIZE = util.NONCE_SIZE // byte
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
