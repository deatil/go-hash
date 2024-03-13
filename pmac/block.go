package pmac

import (
    "crypto/cipher"
    "crypto/subtle"
)

type Block [Size]byte

func (b *Block) Clear() {
    for i := range b {
        b[i] = 0
    }
}

func (b *Block) Dbl() {
    var z byte

    for i := Size - 1; i >= 0; i-- {
        zz := b[i] >> 7
        b[i] = b[i]<<1 | z
        z = zz
    }

    b[Size-1] ^= byte(subtle.ConstantTimeSelect(int(z), R, 0))
}

func (b *Block) Encrypt(c cipher.Block) {
    c.Encrypt(b[:], b[:])
}
