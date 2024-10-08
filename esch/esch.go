package esch

import (
    "hash"
)

// New returns a new hash.Hash computing the ESCH checksum
func New(hashsize int) (hash.Hash, error) {
    return newDigest(hashsize)
}

// ===========

// New256 returns a new hash.Hash computing the ESCH checksum
func New256() hash.Hash {
    h, _ := New(256)
    return h
}

// Sum256 returns the ESCH-256 checksum of the data.
func Sum256(data []byte) (sum256 [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum256[:], sum[:Size256])
    return
}

// ===========

// New384 returns a new hash.Hash computing the ESCH checksum
func New384() hash.Hash {
    h, _ := New(384)
    return h
}

// Sum384 returns the ESCH-384 checksum of the data.
func Sum384(data []byte) (sum384 [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum384[:], sum[:Size384])
    return
}
