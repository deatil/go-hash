package xxh3

// The size of a xxh3_128 hash value in bytes
const Size128 = 16

// The blocksize of xxh3_128 hash function in bytes
const BlockSize128 = INTERNALBUFFER_SIZE

// digest128 represents the partial evaluation of a checksum.
type digest128 struct {
    s   [8]uint64
    x   [BlockSize128]byte
    nx  int
    len uint64

    seed    uint64
    secret []byte

    secretLimit int
    nbStripesSoFar int
    nbStripesPerBlock int
}

// newDigest128 returns a new *digest128 computing the checksum
func newDigest128(seed uint64, secret []byte) *digest128 {
    d := new(digest128)
    d.seed = seed

    d.secret = make([]byte, len(secret))
    copy(d.secret, secret)

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

    // buffer
    d.x = [BlockSize64]byte{}
    // bufferedSize
    d.nx = 0
    d.len = 0

    d.secretLimit = len(d.secret) - STRIPE_LEN
    d.nbStripesSoFar = 0
    d.nbStripesPerBlock = (len(d.secret) - STRIPE_ELTS) / SECRET_CONSUME_RATE
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

    if len(p) == 0 {
        return
    }

    secret := d.secret
    acc := d.s[:]

    if len(p) <= BlockSize64 - d.nx {
        copy(d.x[d.nx:], p)
        d.nx += len(p)
        return
    }

    if d.nx > 0 {
        loadSize := BlockSize64 - d.nx
        copy(d.x[d.nx:], p[:loadSize])

        p = p[loadSize:]

        consumeStripes(
            acc,
            &d.nbStripesSoFar,
            d.nbStripesPerBlock,
            d.x[:],
            INTERNALBUFFER_STRIPES,
            secret,
            d.secretLimit,
        )

        d.nx = 0
    }

    if len(p) > BlockSize64 {
        nbStripes := (len(p) - 1) / STRIPE_LEN

        p = consumeStripes(
            acc,
            &d.nbStripesSoFar,
            d.nbStripesPerBlock,
            p,
            nbStripes,
            secret,
            d.secretLimit,
        )

        if len(p) >= STRIPE_LEN {
            copy(d.x[len(d.x)-STRIPE_LEN:], p[len(p)-STRIPE_LEN:])
        }
    }

    copy(d.x[:], p)
    d.nx = len(p)

    copy(d.s[:], acc)

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
    bytes := sum.Bytes()

    copy(out[:], bytes[:])
    return
}

func (d *digest128) Sum128() Uint128 {
    secret := d.secret

    if d.len > MIDSIZE_MAX {
        acc := make([]uint64, 8)
        d.hashLong(acc, secret)

        return mergeAccs_128b(acc, secret, d.len)
    }

    if d.seed != 0 {
        return Hash_128bits_withSeed(d.x[:d.nx], d.seed)
    }

    return Hash_128bits_withSecret(d.x[:d.nx], secret[d.secretLimit + STRIPE_LEN:])
}

func (d *digest128) hashLong(acc []uint64, secret []byte) {
    var lastStripe [STRIPE_LEN]byte
    var lastStripePtr []byte

    copy(acc, d.s[:])

    if d.nx >= STRIPE_LEN {
        /* Consume remaining stripes then point to remaining data in buffer */
        nbStripes := (d.nx - 1) / STRIPE_LEN
        nbStripesSoFar := d.nbStripesSoFar

        consumeStripes(
            acc,
            &nbStripesSoFar,
            d.nbStripesPerBlock,
            d.x[:d.nx],
            nbStripes,
            secret,
            d.secretLimit,
        )

        lastStripePtr = d.x[d.nx - STRIPE_LEN:]
    } else {
        catchupSize := STRIPE_LEN - d.nx

        copy(lastStripe[:], d.x[len(d.x) - catchupSize:])
        copy(lastStripe[catchupSize:], d.x[:d.nx])

        lastStripePtr = lastStripe[:]
    }

    /* Last stripe */
    accumulate_512(
        acc,
        lastStripePtr,
        secret[:d.secretLimit - SECRET_LASTACC_START],
    )
}

func (d *digest128) compress(data []byte) {
    nbStripesPerBlock := (len(d.secret) - STRIPE_ELTS) / SECRET_CONSUME_RATE

    accumulate(d.s[:], data, d.secret, nbStripesPerBlock)
    scrambleAcc(d.s[:], d.secret[len(d.secret)-STRIPE_LEN:])
}

// checksum128 returns the 64bits Hash value.
func checksum128(data []byte, seed uint64, secret []byte) Uint128 {
    h := newDigest128(seed, secret)
    h.Write(data)

    return h.Sum128()
}
