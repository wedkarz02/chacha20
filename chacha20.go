package chacha20

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
