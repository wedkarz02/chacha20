package chacha20

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/wedkarz02/chacha20/util"
)

func TestNewNonce(t *testing.T) {
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
