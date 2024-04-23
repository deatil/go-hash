package xxh3

// The size of a xxh3_64 hash value in bytes
const Size64 = 8

// The blocksize of xxh3_64 hash function in bytes
const BlockSize64 = BLOCK_LEN

// digest64 represents the partial evaluation of a checksum.
type digest64 struct {
    s   [8]uint64
    x   [BlockSize64]byte
    nx  int
    len uint64

    seed    uint64
    kSecret []uint32
}

// newDigest64 returns a new *digest64 computing the checksum
func newDigest64(seed uint64, secret []byte) *digest64 {
    d := new(digest64)
    d.seed = seed
    d.kSecret = bytesToKeys(secret)
    d.Reset()

    return d
}

func (d *digest64) Reset() {
    d.s = [8]uint64{
        d.seed,
        PRIME64_1,
        PRIME64_2,
        PRIME64_3,
        PRIME64_4,
        PRIME64_5,
        -d.seed,
        0,
    }
    d.x = [BlockSize64]byte{}
    d.nx = 0
    d.len = 0
}

func (d *digest64) Size() int {
    return Size64
}

func (d *digest64) BlockSize() int {
    return BlockSize64
}

func (d *digest64) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)

    var xx int

    plen := len(p)
    for d.nx + plen >= BlockSize64 {
        copy(d.x[d.nx:], p)

        d.compress(d.x[:])

        xx = BlockSize64 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest64) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest64) checkSum() (out [Size64]byte) {
    sum := d.Sum64()
    putu64be(out[:], sum)

    return
}

func (d *digest64) Sum64() uint64 {
    p := d.x[:]
    key := d.kSecret
    seed := d.seed

    if d.len <= 16 {
        return len_0to16_64b(d.x[:d.nx], key, seed)
    }

    acc := PRIME64_1 * (d.len + seed)
    len := d.len
    if len > 32 {
        if len > 64 {
            if len > 96 {
                if len > 128 {
                    return d.hashLong(d.x[:d.nx], seed)
                }

                acc += mix16B(p[48:], key[96/4:])
                acc += mix16B(p[len-64:], key[112/4:])
            }

            acc += mix16B(p[32:], key[64/4:])
            acc += mix16B(p[len-48:], key[80/4:])
        }

        acc += mix16B(p[16:], key[32/4:])
        acc += mix16B(p[len-32:], key[48/4:])

    }

    acc += mix16B(p[0:], key[0:])
    acc += mix16B(p[len-16:], key[4:])

    return avalanche(acc)
}

func (d *digest64) hashLong(data []byte, seed uint64) uint64 {
    // last partial block
    nbStripes := (int(d.len) % BLOCK_LEN) / STRIPE_LEN
    accumulate(d.s[:], d.x[:d.nx], d.kSecret[:], nbStripes)

    // last stripe
    if (len(data) & (STRIPE_LEN - 1)) != 0 {
        p := data[len(data)-STRIPE_LEN:]
        accumulate_512(d.s[:], p, d.kSecret[nbStripes*2:])
    }

    // converge into final hash
    return mergeAccs(d.s[:], d.kSecret, d.len * PRIME64_1)
}

func (d *digest64) compress(data []byte) {
    accumulate_full(d.s[:], data, d.kSecret[:], NB_KEYS)
    scrambleAcc(d.s[:], d.kSecret[KEYSET_DEFAULT_SIZE-STRIPE_ELTS:])
}

// checksum64 returns the 64bits Hash value.
func checksum64(data []byte, seed uint64, secret []byte) uint64 {
    h := newDigest64(seed, secret)
    h.Write(data)

    return h.Sum64()
}
