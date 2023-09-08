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

// Package poly implements the Poly1305 Message Authentication
// Code algorithm.
//
// It was coded referencing RFC	8439:
//
// https://datatracker.ietf.org/doc/html/rfc8439#section-2.5
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
