// PMAC message authentication code, defined in
// https://web.cs.ucdavis.edu/~rogaway/ocb/pmac.pdf
package pmac

import (
    "hash"
    "math/bits"
    "crypto/cipher"
    "crypto/subtle"
)

const (
    Size = 16
    BlockSize = 16
    R = 0x87
)

const precomputedBlocks = 31

type pmac struct {
    c cipher.Block
    l [precomputedBlocks]Block
    lInv Block
    digest Block
    offset Block
    buf Block
    pos uint
    ctr uint
    finished bool
}

func New(c cipher.Block) hash.Hash {
    if c.BlockSize() != Size {
        panic("pmac: invalid cipher block size")
    }

    d := new(pmac)
    d.c = c

    var tmp Block
    tmp.Encrypt(c)

    for i := range d.l {
        copy(d.l[i][:], tmp[:])
        tmp.Dbl()
    }

    copy(tmp[:], d.l[0][:])
    lastBit := int(tmp[Size-1] & 0x01)

    for i := Size - 1; i > 0; i-- {
        carry := byte(subtle.ConstantTimeSelect(int(tmp[i-1]&1), 0x80, 0))
        tmp[i] = (tmp[i] >> 1) | carry
    }

    tmp[0] >>= 1
    tmp[0] ^= byte(subtle.ConstantTimeSelect(lastBit, 0x80, 0))
    tmp[Size-1] ^= byte(subtle.ConstantTimeSelect(lastBit, R>>1, 0))
    copy(d.lInv[:], tmp[:])

    return d
}

func (d *pmac) Reset() {
    d.digest.Clear()
    d.offset.Clear()
    d.buf.Clear()
    d.pos = 0
    d.ctr = 0
    d.finished = false
}

func (d *pmac) Size() int {
    return Size
}

func (d *pmac) BlockSize() int {
    return BlockSize
}

func (d *pmac) Write(msg []byte) (int, error) {
    if d.finished {
        panic("pmac: already finished")
    }

    var msgPos, msgLen, remaining uint
    msgLen = uint(len(msg))
    remaining = Size - d.pos

    if msgLen > remaining {
        copy(d.buf[d.pos:], msg[:remaining])

        msgPos += remaining
        msgLen -= remaining

        d.processBuffer()
    }

    for msgLen > Size {
        copy(d.buf[:], msg[msgPos:msgPos+Size])

        msgPos += Size
        msgLen -= Size

        d.processBuffer()
    }

    if msgLen > 0 {
        copy(d.buf[d.pos:d.pos+msgLen], msg[msgPos:])
        d.pos += msgLen
    }

    return len(msg), nil
}

func (d *pmac) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *pmac) checkSum() [Size]byte {
    if d.finished {
        panic("pmac: already finished")
    }

    if d.pos == Size {
        xor(d.digest[:], d.buf[:])
        xor(d.digest[:], d.lInv[:])
    } else {
        xor(d.digest[:], d.buf[:d.pos])
        d.digest[d.pos] ^= 0x80
    }

    d.digest.Encrypt(d.c)
    d.finished = true

    return d.digest
}

func (d *pmac) processBuffer() {
    xor(d.offset[:], d.l[bits.TrailingZeros(d.ctr+1)][:])
    xor(d.buf[:], d.offset[:])
    d.ctr++

    d.buf.Encrypt(d.c)
    xor(d.digest[:], d.buf[:])
    d.pos = 0
}

func xor(a, b []byte) {
    for i, v := range b {
        a[i] ^= v
    }
}
