package xxh3

import (
    "unsafe"
    "reflect"
    "math/bits"
    "encoding/binary"
)

// Endianness option
const littleEndian bool = true

func getu32(ptr []byte) uint32 {
    if littleEndian {
        return binary.LittleEndian.Uint32(ptr)
    } else {
        return binary.BigEndian.Uint32(ptr)
    }
}

func putu32(ptr []byte, a uint32) {
    if littleEndian {
        binary.LittleEndian.PutUint32(ptr, a)
    } else {
        binary.BigEndian.PutUint32(ptr, a)
    }
}

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func putu64be(ptr []byte, a uint64) {
    binary.BigEndian.PutUint64(ptr, a)
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint32(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint32(b[j:])
        }
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        if littleEndian {
            binary.LittleEndian.PutUint32(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint32(dst[j:], w[i])
        }
    }

    return dst
}

func bytesToKeys(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

func rotl32(x uint32, n uint) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func rotr32(x uint32, n uint) uint32 {
    return rotl32(x, 32 - n)
}

func swap32(x uint32) uint32 {
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff )
}

func swap64(x uint64) uint64 {
    return  ((x << 56) & 0xff00000000000000) |
            ((x << 40) & 0x00ff000000000000) |
            ((x << 24) & 0x0000ff0000000000) |
            ((x << 8)  & 0x000000ff00000000) |
            ((x >> 8)  & 0x00000000ff000000) |
            ((x >> 24) & 0x0000000000ff0000) |
            ((x >> 40) & 0x000000000000ff00) |
            ((x >> 56) & 0x00000000000000ff)
}

// =========

func toUint64s(k []uint32) []uint64 {
    hdr := *(*reflect.SliceHeader)(unsafe.Pointer(&k))
    hdr.Len, hdr.Cap = hdr.Len/2, hdr.Cap/2
    return *(*[]uint64)(unsafe.Pointer(&hdr))
}

func mult32to64(a uint32, b uint64) uint64 {
    return uint64(a) * uint64(b)
}

func readKey64(ptr []uint64) uint64 {
    return ptr[0]
}

func mul128(a, b uint64) uint64 {
    hi, lo := bits.Mul64(a, b)
    return hi + lo
}

func avalanche(h64 uint64) uint64 {
    h64 ^= h64 >> 29
    h64 *= PRIME64_3
    h64 ^= h64 >> 32
    return h64
}

func len_1to3_64b(data []byte, key32 []uint32, seed uint64) uint64 {
    c1 := data[0]
    c2 := data[len(data)>>1]
    c3 := data[len(data)-1]
    l1 := uint32(c1) + (uint32(c2) << 8)
    l2 := uint32(len(data)) + (uint32(c3) << 2)
    ll11 := mult32to64(l1+uint32(seed)+key32[0], uint64(l2)+uint64(key32[1]))
    return avalanche(ll11)
}

func len_4to8_64b(data []byte, key32 []uint32, seed uint64) uint64 {
    acc := PRIME64_1 * (uint64(len(data)) + seed)
    l1 := getu32(data[0:4]) + key32[0]
    l2 := getu32(data[len(data)-4:len(data)-4+4]) + key32[1]
    acc += mult32to64(l1, uint64(l2))
    return avalanche(acc)
}

func len_9to16_64b(data []byte, kKey []uint32, seed uint64) uint64 {
    var key64 []uint64 = toUint64s(kKey)

    acc := PRIME64_1 * (uint64(len(data)) + seed)
    ll1 := getu64(data) + key64[0]
    ll2 := getu64(data[len(data)-8:]) + key64[1]
    acc += mul128(ll1, ll2)

    return avalanche(acc)
}

func len_0to16_64b(data []byte, key32 []uint32, seed uint64) uint64 {
    if len(data) > 8 {
        return len_9to16_64b(data, key32, seed)
    }
    if len(data) >= 4 {
        return len_4to8_64b(data, key32, seed)
    }
    if len(data) > 0 {
        return len_1to3_64b(data, key32, seed)
    }

    return seed
}

func accumulate_512(acc []uint64, data []byte, key []uint32) {
    var left, right int
    var dataLeft, dataRight uint32

    _ = acc[7]
    _ = data[63]
    _ = key[15]

    for i := 0; i < 8; i++ {
        left, right = i*2, i*2+1
        dataLeft = getu32(data[4*left:])
        dataRight = getu32(data[4*right:])
        acc[i] += mult32to64(dataLeft+key[left], uint64(dataRight+key[right]))
        acc[i] += uint64(dataLeft) + (uint64(dataRight) << 32)
    }
}

func scrambleAcc(acc []uint64, key []uint32) {
    var left, right int
    var p1, p2 uint64

    _ = acc[7]
    _ = key[15]

    for i := 0; i < 8; i++ {
        left, right = i*2, i*2+1
        acc[i] ^= acc[i] >> 47
        p1 = mult32to64(uint32(acc[i]), uint64(key[left]))
        p2 = mult32to64(uint32(acc[i]>>32), uint64(key[right]))
        acc[i] = p1 ^ p2
    }
}

func accumulate_full(acc []uint64, data []byte, key []uint32, nbStripes int) {
    _ = key[31]
    _ = data[15*STRIPE_LEN:]

    for i := 0; i < 16; i++ {
        accumulate_512(acc, data[i*STRIPE_LEN:], key[i*2:])
    }
}

func accumulate(acc []uint64, data []byte, key []uint32, nbStripes int) {
    for n := 0; n < nbStripes; n++ {
        accumulate_512(acc, data[n*STRIPE_LEN:], key)
        key = key[2:]
    }
}

func mix16B(data []byte, key []uint32) uint64 {
    key64 := toUint64s(key)

    return mul128(
        getu64(data) ^ readKey64(key64),
        getu64(data[8:]) ^ key64[1],
    )
}

func mix2Accs(acc []uint64, key []uint32) uint64 {
    key64 := toUint64s(key)

    return mul128(
        acc[0] ^ readKey64(key64),
        acc[1] ^ key64[1],
    )
}

func mergeAccs(acc []uint64, key []uint32, start uint64) uint64 {
    result64 := start

    for i := 0; i < 8; i += 2 {
        result64 += mix2Accs(acc[i:], key[i*2:])
    }

    return avalanche(result64)
}

// =============

// XXH128_hash_t
type XXH128Hash struct {
    low64, high64 uint64
}

func mul128_fold64(lhs, rhs uint64) uint64 {
    product := mult64to128(lhs, rhs)
    return product.low64 ^ product.high64
}

func xorshift64(v64 uint64, shift int) uint64 {
    return v64 ^ (v64 >> shift)
}

func mult64to128(lhs, rhs uint64) XXH128Hash {
    /* First calculate all of the cross products. */
    lo_lo := mult32to64(uint32(lhs & 0xFFFFFFFF), (rhs & 0xFFFFFFFF))
    hi_lo := mult32to64(uint32(lhs >> 32),        (rhs & 0xFFFFFFFF))
    lo_hi := mult32to64(uint32(lhs & 0xFFFFFFFF), (rhs >> 32))
    hi_hi := mult32to64(uint32(lhs >> 32),        (rhs >> 32))

    /* Now add the products together. These will never overflow. */
    cross := (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi
    upper := (hi_lo >> 32) + (cross >> 32)        + hi_hi
    lower := (cross << 32) | (lo_lo & 0xFFFFFFFF)

    var r128 XXH128Hash
    r128.low64  = lower
    r128.high64 = upper

    return r128
}

func len_1to3_128b(data []byte, secret []byte, seed uint64) XXH128Hash {
    c1 := data[0]
    c2 := data[len(data)>>1]
    c3 := data[len(data)-1]

    len := len(data)

    var combinedl uint32 = (uint32(c1) << 16) |
                           (uint32(c2) << 24) |
                           (uint32(c3) <<  0) |
                           (uint32(len) << 8)
    var combinedh uint32 = rotl32(swap32(combinedl), 13)

    var bitflipl uint64 = uint64(getu32(secret[0:]) ^ getu32(secret[4:])) + seed
    var bitfliph uint64 = uint64(getu32(secret[8:]) ^ getu32(secret[12:])) - seed

    var keyed_lo uint64 = uint64(combinedl) ^ bitflipl
    var keyed_hi uint64 = uint64(combinedh) ^ bitfliph

    var h128 XXH128Hash
    h128.low64  = avalanche(keyed_lo)
    h128.high64 = avalanche(keyed_hi)

    return h128
}

func len_4to8_128b(input []byte, secret []byte, seed uint64) XXH128Hash {
    seed ^= uint64(swap32(uint32(seed))) << 32

    len := len(input)

    var input_lo uint32 = getu32(input)
    var input_hi uint32 = getu32(input[len - 4:])
    var input_64 uint64 = uint64(input_lo) + (uint64(input_hi) << 32)
    var bitflip uint64 = getu64(secret[16:]) ^ getu64(secret[24:]) + seed
    var keyed uint64 = input_64 ^ bitflip

    /* Shift len to the left to ensure it is even, this avoids even multiplies. */
    m128 := mult64to128(keyed, uint64(PRIME64_1) + uint64(len << 2))

    m128.high64 += (m128.low64 << 1)
    m128.low64  ^= (m128.high64 >> 3)

    m128.low64   = xorshift64(m128.low64, 35)
    m128.low64  *= PRIME_MX2
    m128.low64   = xorshift64(m128.low64, 28)
    m128.high64  = avalanche(m128.high64)

    return m128
}

func len_9to16_128b(input []byte, secret []byte, seed uint64) XXH128Hash {
    len := len(input)

    bitflipl := getu64(secret[32:]) ^ getu64(secret[40:]) - seed
    bitfliph := getu64(secret[48:]) ^ getu64(secret[56:]) + seed
    input_lo := getu64(input[0:])
    input_hi := getu64(input[len - 8:])

    m128 := mult64to128(input_lo ^ input_hi ^ bitflipl, uint64(PRIME64_1))

    m128.low64 += uint64(len - 1) << 54
    input_hi   ^= bitfliph

    m128.high64 += input_hi + mult32to64(uint32(input_hi), PRIME32_2 - 1)

    /* m128 ^= XXH_swap64(m128 >> 64); */
    m128.low64  ^= swap64(m128.high64)

    /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
    h128 := mult64to128(m128.low64, PRIME64_2)
    h128.high64 += m128.high64 * PRIME64_2

    h128.low64   = avalanche(h128.low64)
    h128.high64  = avalanche(h128.high64)

    return h128
}

func len_0to16_128b(input []byte, secret []byte, seed uint64) XXH128Hash {
    len := len(input)

    if len > 8 {
        return len_9to16_128b(input, secret, seed)
    }
    if len >= 4 {
        return len_4to8_128b(input, secret, seed)
    }
    if len > 0 {
        return len_1to3_128b(input, secret, seed)
    }

    var h128 XXH128Hash
    bitflipl := getu64(secret[64:]) ^ getu64(secret[72:])
    bitfliph := getu64(secret[80:]) ^ getu64(secret[88:])

    h128.low64 = avalanche(seed ^ bitflipl)
    h128.high64 = avalanche(seed ^ bitfliph)
    return h128
}

func mix16B_128b(input []byte, secret []byte, seed64 uint64) uint64 {
    input_lo := getu64(input[0:])
    input_hi := getu64(input[8:])

    return mul128_fold64(
        input_lo ^ (getu64(secret[0:]) + seed64),
        input_hi ^ (getu64(secret[8:]) - seed64),
    )
}

func mix32B(
    acc     XXH128Hash,
    input_1 []byte,
    input_2 []byte,
    secret  []byte,
    seed    uint64,
) XXH128Hash {
    acc.low64  += mix16B_128b(input_1, secret[0:], seed)
    acc.low64  ^= getu64(input_2) + getu64(input_2[8:])
    acc.high64 += mix16B_128b(input_2, secret[16:], seed)
    acc.high64 ^= getu64(input_1) + getu64(input_1[8:])
    return acc
}

func len_17to128_128b(input []byte, secret []byte, seed uint64) XXH128Hash {
    len := len(input)

    var acc XXH128Hash
    acc.low64 = uint64(len) * uint64(PRIME64_1)
    acc.high64 = 0

    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = mix32B(acc, input[48:], input[len-64:], secret[96:], seed)
            }

            acc = mix32B(acc, input[32:], input[len-48:], secret[64:], seed)
        }

        acc = mix32B(acc, input[16:], input[len-32:], secret[32:], seed)
    }

    acc = mix32B(acc, input, input[len-16:], secret, seed)

    var h128 XXH128Hash
    h128.low64  = acc.low64 + acc.high64
    h128.high64 = (acc.low64    * uint64(PRIME64_1)) +
                  (acc.high64   * uint64(PRIME64_4)) +
                  ((uint64(len) - seed) * uint64(PRIME64_2))
    h128.low64  = avalanche(h128.low64)
    h128.high64 = 0 - avalanche(h128.high64)
    return h128
}

func len_129to240_128b(input []byte, secret []byte, seed uint64) XXH128Hash {
    var i int
    var acc XXH128Hash

    len := len(input)

    acc.low64 = uint64(len) * uint64(PRIME64_1)
    acc.high64 = 0

    for i = 32; i < 160; i += 32 {
        acc = mix32B(
                acc,
                input[i - 32:],
                input[i - 16:],
                secret[i - 32:],
                seed,
            )
    }

    acc.low64 = avalanche(acc.low64)
    acc.high64 = avalanche(acc.high64)

    for i = 160; i <= len; i += 32 {
        acc = mix32B(
                acc,
                input[i - 32:],
                input[i - 16:],
                secret[MIDSIZE_STARTOFFSET + i - 160:],
                seed,
           )
    }

    /* last bytes */
    acc = mix32B(
            acc,
            input[len - 16:],
            input[len - 32:],
            secret[SECRET_SIZE_MIN - MIDSIZE_LASTOFFSET - 16:],
            0 - seed,
        )

    var h128 XXH128Hash
    h128.low64  = acc.low64 + acc.high64
    h128.high64 = (acc.low64    * uint64(PRIME64_1)) +
                  (acc.high64   * uint64(PRIME64_4)) +
                  ((uint64(len) - seed) * uint64(PRIME64_2))
    h128.low64  = avalanche(h128.low64)
    h128.high64 = 0 - avalanche(h128.high64)
    return h128
}

func mix2Accs_128b(acc []uint64, secret []byte) uint64 {
    return  mul128_fold64(
               acc[0] ^ getu64(secret[0:]),
               acc[1] ^ getu64(secret[8:]),
            )
}

func mergeAccs_128b(acc []uint64, secret []byte, start uint64) uint64 {
    result64 := start

    for i := 0; i < 4; i++ {
        result64 += mix2Accs_128b(acc[2*i:], secret[16*i:])
    }

    return avalanche(result64)
}

func hashLong_128b_mergeAccs(
    acc []uint64,
    secret []byte,
    length uint64,
) XXH128Hash {
    var h128 XXH128Hash
    h128.low64  = mergeAccs_128b(
                     acc,
                     secret[SECRET_MERGEACCS_START:],
                     length * uint64(PRIME64_1),
                  )
    h128.high64 = mergeAccs_128b(
                    acc,
                    secret[len(secret) - len(acc)*8 - SECRET_MERGEACCS_START:],
                    ^(length * uint64(PRIME64_2)),
                 );
    return h128
}
