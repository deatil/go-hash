package kupyna

import (
    "hash"
)

// kmac512 represents the partial evaluation of a checksum.
type kmac512 struct {
    h hash.Hash
    ik [64]byte
    len uint64
}

// NewKmac512 returns a new hash.Hash computing the kmac512 checksum
func NewKmac512(key []byte) (hash.Hash, error) {
    l := len(key)
    if l != 64 {
        return nil, KeySizeError(l)
    }

    d := new(kmac512)
    d.h = New512()
    d.Reset()
    d.init(key)

    return d, nil
}

func (d *kmac512) init(key []byte) {
    d.h.Write(key)
    d.h.Write(kpad64[:])

    d.len = 0
    for i := 0; i < 64; i++ {
        d.ik[i] = ^key[i]
    }
}

func (d *kmac512) Reset() {
    d.h.Reset()
}

func (d *kmac512) Size() int {
    return d.h.Size()
}

func (d *kmac512) BlockSize() int {
    return d.h.BlockSize()
}

func (d *kmac512) Write(p []byte) (nn int, err error) {
    d.len += uint64(len(p))
    return d.h.Write(p)
}

func (d *kmac512) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *kmac512) checkSum() []byte {
    var n uint64 = d.len
    var pad_size uint64

    if n < 116 {
        pad_size = 115 - n
    } else {
        pad_size = 127 - ((n - 116) % 128)
    }

    n = n * 8

    d.h.Write(dpad[:pad_size + 1])

    nbytes := uint64sToBytes([]uint64{n})
    d.h.Write(nbytes)

    d.h.Write(dpad[16:20])
    d.h.Write(d.ik[:])

    hash := d.h.Sum(nil)
    return hash
}
