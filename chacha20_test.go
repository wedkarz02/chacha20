package chacha20

import (
	"fmt"
	"reflect"
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

	printState(c.state)
}

func printState(state [16]uint32) {
	for i, num := range state {
		if i%4 == 0 {
			fmt.Println()
		}

		fmt.Printf("%08x ", num)
	}
	fmt.Println()
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
