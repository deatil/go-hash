package xxh3

// New128 returns a new Hash128 computing the echo checksum
func New128() Hash128 {
    return New128WithSeed(0)
}

// New128WithSecret returns a new Hash128 computing the echo checksum
func New128WithSecret(secret []byte) Hash128 {
    return newDigest128(0, secret)
}

// New128WithSeed returns a new Hash128 computing the echo checksum
func New128WithSeed(seed uint64) Hash128 {
    return newDigest128(seed, kSecret)
}

// New128WithSecretandSeed returns a new Hash128 computing the echo checksum
func New128WithSecretandSeed(secret []byte, seed uint64) Hash128 {
    return newDigest128(seed, secret)
}

// Checksum returns the 128bits Hash value.
func Sum128(input []byte) (out [Size128]byte) {
    sum := checksum128(input, 0, kSecret)
    putu64be(out[:], sum.low64)
    putu64be(out[Size128/2:], sum.high64)

    return
}

// Checksum returns the 128bits Hash value.
func Sum128WithSeed(input []byte, seed uint64) (out [Size128]byte) {
    sum := checksum128(input, seed, kSecret)
    putu64be(out[:], sum.low64)
    putu64be(out[Size128/2:], sum.high64)

    return
}
