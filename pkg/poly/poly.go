package poly

import (
	"errors"
)

const (
	TAG_SIZE = 16
	R_SIZE   = 16
	S_SIZE   = 16
	PRIME_P  = 0x3fffffffffffffffffffffffffffffffb
)

var ErrPolyKeySize = errors.New("invalid poly1305 key size")

func clamp(r []byte) {
	r[3] &= 15
	r[7] &= 15
	r[11] &= 15
	r[15] &= 15
	r[4] &= 252
	r[8] &= 252
	r[12] &= 252
}
