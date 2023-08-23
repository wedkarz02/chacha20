package util

const COUNTER_SIZE = 4

type Counter struct {
	Bytes [COUNTER_SIZE]byte
}

func NewCounter() *Counter {
	return &Counter{}
}

func (c *Counter) Increment() {
	for i := COUNTER_SIZE - 1; i >= 0; i-- {
		c.Bytes[i]++
		if c.Bytes[i] != 0 {
			break
		}
	}
}
