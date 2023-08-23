package util

import (
	"crypto/rand"
	"errors"
	"io"
)

const NONCE_SIZE = 12

var ErrSeed = errors.New("nonce seeding failed")

type Nonce struct {
	Bytes [NONCE_SIZE]byte
}

func NewNonce() (*Nonce, error) {
	n := Nonce{}

	if err := n.seed(); err != nil {
		return nil, err
	}

	return &n, nil
}

func (n *Nonce) seed() error {
	if _, err := io.ReadFull(rand.Reader, n.Bytes[:]); err != nil {
		return ErrSeed
	}

	return nil
}
