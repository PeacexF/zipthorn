package generator

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
)

const payloadBlock = 32 << 10

type filler struct {
	rng   *rand.Rand
	ratio float64
	fill  byte
	buf   []byte
}

func newFiller(rng *rand.Rand, ratio float64) *filler {
	if ratio < 1 {
		ratio = 1
	}
	return &filler{
		rng:   rng,
		ratio: ratio,
		fill:  byte(rng.Uint32()),
		buf:   make([]byte, payloadBlock),
	}
}

func (f *filler) writeTo(w io.Writer, n int64) error {
	for n > 0 {
		b := int64(payloadBlock)
		if b > n {
			b = n
		}
		f.block(f.buf[:b])
		if _, err := w.Write(f.buf[:b]); err != nil {
			return err
		}
		n -= b
	}
	return nil
}

func (f *filler) block(b []byte) {
	n := min(int(float64(len(b))/f.ratio+0.5), len(b))
	var word [8]byte
	for i := 0; i < n; i += len(word) {
		binary.LittleEndian.PutUint64(word[:], f.rng.Uint64())
		copy(b[i:min(i+len(word), n)], word[:])
	}
	for i := n; i < len(b); i++ {
		b[i] = f.fill
	}
}
