package chacha20

import (
	"fmt"
	"testing"

	"github.com/wedkarz02/chacha20/util"
)

func TestNonce(t *testing.T) {
	n, err := util.NewNonce()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(n.Bytes[:]))
	fmt.Println(len(n.Bytes))
}

func TestNewCipher(t *testing.T) {
	c, err := NewCipher([]byte("asdf"))
	if err != nil {
		panic(err)
	}

	for i := 0; i < 0xffe; i++ {
		c.state[12]++
	}

	for i, word := range c.state {
		if i%4 == 0 {
			fmt.Println()
		}

		fmt.Printf("%08x ", word)
	}
}
