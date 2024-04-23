package xxh3

// The size of a xxh3_128 hash value in bytes
const Size128 = 16

// The blocksize of xxh3_128 hash function in bytes
const BlockSize128 = BLOCK_LEN

// digest128 represents the partial evaluation of a checksum.
type digest128 struct {
    s   [8]uint64
    x   [BlockSize128]byte
    nx  int
    len uint64

    seed    uint64
    kSecret []byte
}

// newDigest128 returns a new *digest128 computing the checksum
func newDigest128(seed uint64, secret []byte) *digest128 {
    d := new(digest128)
    d.seed = seed

    d.kSecret = make([]byte, len(secret))
    copy(d.kSecret, secret)

    d.Reset()

    return d
}

func (d *digest128) Reset() {
    d.s = [8]uint64{
        PRIME32_3, PRIME64_1,
        PRIME64_2, PRIME64_3,
        PRIME64_4, PRIME32_2,
        PRIME64_5, PRIME32_1,
    }
    d.x = [BlockSize128]byte{}
    d.nx = 0
    d.len = 0
}

func (d *digest128) Size() int {
    return Size128
}

func (d *digest128) BlockSize() int {
    return BlockSize128
}

func (d *digest128) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)

    var xx int

    plen := len(p)
    for d.nx + plen >= BlockSize128 {
        copy(d.x[d.nx:], p)

        d.compress(d.x[:])

        xx = BlockSize128 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest128) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest128) checkSum() (out [Size128]byte) {
    sum := d.Sum128()
    putu64be(out[:], sum.low64)
    putu64be(out[Size128/2:], sum.high64)

    return
}

func (d *digest128) Sum128() XXH128Hash {
    key := d.kSecret
    seed := d.seed

    if d.len <= 16 {
        return len_0to16_128b(d.x[:d.nx], key, seed)
    } else if d.len <= 128 {
        return len_17to128_128b(d.x[:d.nx], key, seed)
    } else if d.len <= XXH3_MIDSIZE_MAX {
        return len_129to240_128b(d.x[:d.nx], key, seed)
    }

    return d.hashLong(d.x[:d.nx], seed)
}

func (d *digest128) hashLong(data []byte, seed uint64) XXH128Hash {
    secret := bytesToKeys(d.kSecret)

    // last partial block
    nbStripes := (int(d.len) % BLOCK_LEN) / STRIPE_LEN
    accumulate(d.s[:], d.x[:d.nx], secret[:], nbStripes)

    // last stripe
    if (len(data) & (STRIPE_LEN - 1)) != 0 {
        p := data[len(data)-STRIPE_LEN:]
        accumulate_512(d.s[:], p, secret[nbStripes*2:])
    }

    // converge into final hash
    return hashLong_128b_mergeAccs(d.s[:], d.kSecret, d.len)
}

func (d *digest128) compress(data []byte) {
    secret := bytesToKeys(d.kSecret)

    accumulate_full(d.s[:], data, secret, NB_KEYS)
    scrambleAcc(d.s[:], secret[KEYSET_DEFAULT_SIZE-STRIPE_ELTS:])
}

// checksum128 returns the 64bits Hash value.
func checksum128(data []byte, seed uint64, secret []byte) XXH128Hash {
    h := newDigest128(seed, secret)
    h.Write(data)

    return h.Sum128()
}
