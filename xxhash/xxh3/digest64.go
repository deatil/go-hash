package xxh3

// The size of a xxh3_64 hash value in bytes
const Size64 = 8

// The blocksize of xxh3_64 hash function in bytes
const BlockSize64 = INTERNALBUFFER_SIZE

// digest64 represents the partial evaluation of a checksum.
type digest64 struct {
    s   [8]uint64
    x   [BlockSize64]byte
    nx  int
    len uint64

    seed    uint64
    secret []byte

    secretLimit int
    nbStripesSoFar int
    nbStripesPerBlock int
}

// newDigest64 returns a new *digest64 computing the checksum
func newDigest64(seed uint64, secret []byte) *digest64 {
    d := new(digest64)
    d.seed = seed

    d.secret = make([]byte, len(secret))
    copy(d.secret, secret)

    d.Reset()

    return d
}

func (d *digest64) Reset() {
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

func (d *digest64) Size() int {
    return Size64
}

func (d *digest64) BlockSize() int {
    return BlockSize64
}

func (d *digest64) Write(p []byte) (nn int, err error) {
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
    secret := d.secret

    if d.len > MIDSIZE_MAX {
        acc := make([]uint64, 8)
        d.hashLong(acc, secret)

        return mergeAccs(
            acc,
            secret[SECRET_MERGEACCS_START:],
            d.len * PRIME64_1,
        )
    }

    if d.seed != 0 {
        return Hash_64bits_withSeed(d.x[:d.nx], d.seed)
    }

    return Hash_64bits_withSecret(d.x[:d.nx], secret[d.secretLimit + STRIPE_LEN:])
}

func (d *digest64) hashLong(acc []uint64, secret []byte) {
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

// checksum64 returns the 64bits Hash value.
func checksum64(data []byte, seed uint64, secret []byte) uint64 {
    h := newDigest64(seed, secret)
    h.Write(data)

    return h.Sum64()
}
