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

func TestCounter(t *testing.T) {
	ctr := util.NewCounter()

	fmt.Println(len(ctr.Bytes))
	for i := 0; i < 256; i++ {
		ctr.Increment()
		for _, b := range ctr.Bytes {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()
	}
}
