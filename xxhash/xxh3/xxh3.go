package xxh3

import (
    "hash"
)

// Hash128
type Hash128 interface {
    hash.Hash
    Sum128() XXH128Hash
}
