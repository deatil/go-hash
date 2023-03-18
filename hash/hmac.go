package hash

import (
    "hash"
    "hash/adler32"
    "crypto/md5"
    "crypto/sha1"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"

    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/sha3"
    "golang.org/x/crypto/ripemd160"
    "github.com/deatil/go-hash/md2"
)

// NewHmac
// HMAC (Hash-based Message Authentication Code) 常用于接口签名验证
// 支持的算法有:
// md5、sha1、sha256、sha512、adler32、crc32、crc32b、crc32c、
// fnv132、fnv164、fnv1a32、fnv1a64、
// gost、gost-crypto、haval128,3、haval128,4、haval128,5、
// haval160,3、haval160,4、haval160,5、haval192,3、haval192,4、
// haval192,5、haval224,3、haval224,4、haval224,5、haval256,3、
// haval256,4、haval256,5、joaat、md2、md4、
// ripemd128、ripemd160、ripemd256、ripemd320、
// sha224、sha3-224、sha3-256、sha3-384、sha3-512、
// sha384、sha512/224、sha512/256、
// snefru、snefru256、tiger128,3、tiger128,4、tiger160,3、
// tiger160,4、tiger192,3、tiger192,4、whirlpool
func (this Hash) NewHmac(h func() hash.Hash, secret []byte) Hash {
    this.hash = hmac.New(h, secret)

    return this
}

// ============================================

var (
    newAdler32 = func() hash.Hash {
        return adler32.New()
    }
)

// HmacAdler32 哈希值
func (this Hash) HmacAdler32(secret []byte) Hash {
    this.data = hmacHash(newAdler32, this.data, secret)

    return this
}

// NewHmacAdler32
func (this Hash) NewHmacAdler32(secret []byte) Hash {
    return this.NewHmac(newAdler32, secret)
}

// ============================================

// HmacMd2 哈希值
func (this Hash) HmacMd2(secret []byte) Hash {
    this.data = hmacHash(md2.New, this.data, secret)

    return this
}

// NewHmacMd2
func (this Hash) NewHmacMd2(secret []byte) Hash {
    return this.NewHmac(md2.New, secret)
}

// ============================================

// HmacMd4 哈希值
func (this Hash) HmacMd4(secret []byte) Hash {
    this.data = hmacHash(md4.New, this.data, secret)

    return this
}

// NewHmacMd4
func (this Hash) NewHmacMd4(secret []byte) Hash {
    return this.NewHmac(md4.New, secret)
}

// ============================================

// HmacMd5 哈希值
func (this Hash) HmacMd5(secret []byte) Hash {
    this.data = hmacHash(md5.New, this.data, secret)

    return this
}

// NewHmacMd5
func (this Hash) NewHmacMd5(secret []byte) Hash {
    return this.NewHmac(md5.New, secret)
}

// ============================================

// HmacSHA1 哈希值
func (this Hash) HmacSHA1(secret []byte) Hash {
    this.data = hmacHash(sha1.New, this.data, secret)

    return this
}

// NewHmacSHA1
func (this Hash) NewHmacSHA1(secret []byte) Hash {
    return this.NewHmac(sha1.New, secret)
}

// ============================================

// HmacSha224 哈希值
func (this Hash) HmacSha224(secret []byte) Hash {
    this.data = hmacHash(sha256.New224, this.data, secret)

    return this
}

// NewHmacSha224
func (this Hash) NewHmacSha224(secret []byte) Hash {
    return this.NewHmac(sha256.New224, secret)
}

// ============================================

// HmacSha256 哈希值
func (this Hash) HmacSha256(secret []byte) Hash {
    this.data = hmacHash(sha256.New, this.data, secret)

    return this
}

// NewHmacSha256
func (this Hash) NewHmacSha256(secret []byte) Hash {
    return this.NewHmac(sha256.New, secret)
}

// ============================================

// HmacSha384 哈希值
func (this Hash) HmacSha384(secret []byte) Hash {
    this.data = hmacHash(sha512.New384, this.data, secret)

    return this
}

// NewHmacSha384
func (this Hash) NewHmacSha384(secret []byte) Hash {
    return this.NewHmac(sha512.New384, secret)
}

// ============================================

// HmacSha512 哈希值
func (this Hash) HmacSha512(secret []byte) Hash {
    this.data = hmacHash(sha512.New, this.data, secret)

    return this
}

// NewHmacSha512
func (this Hash) NewHmacSha512(secret []byte) Hash {
    return this.NewHmac(sha512.New, secret)
}

// ============================================

// HmacSha512_224 哈希值
func (this Hash) HmacSha512_224(secret []byte) Hash {
    this.data = hmacHash(sha512.New512_224, this.data, secret)

    return this
}

// NewHmacSha512_224
func (this Hash) NewHmacSha512_224(secret []byte) Hash {
    return this.NewHmac(sha512.New512_224, secret)
}

// ============================================

// HmacSha512_256 哈希值
func (this Hash) HmacSha512_256(secret []byte) Hash {
    this.data = hmacHash(sha512.New512_256, this.data, secret)

    return this
}

// NewHmacSha512_256
func (this Hash) NewHmacSha512_256(secret []byte) Hash {
    return this.NewHmac(sha512.New512_256, secret)
}

// ============================================

// HmacRipemd160 哈希值
func (this Hash) HmacRipemd160(secret []byte) Hash {
    this.data = hmacHash(ripemd160.New, this.data, secret)

    return this
}

// NewHmacRipemd160
func (this Hash) NewHmacRipemd160(secret []byte) Hash {
    return this.NewHmac(ripemd160.New, secret)
}

// ============================================

// HmacSHA3_224 哈希值
func (this Hash) HmacSHA3_224(secret []byte) Hash {
    this.data = hmacHash(sha3.New224, this.data, secret)

    return this
}

// NewHmacSHA3_224
func (this Hash) NewHmacSHA3_224(secret []byte) Hash {
    return this.NewHmac(sha3.New224, secret)
}

// ============================================

// HmacSHA3_256 哈希值
func (this Hash) HmacSHA3_256(secret []byte) Hash {
    this.data = hmacHash(sha3.New256, this.data, secret)

    return this
}

// NewHmacSHA3_256
func (this Hash) NewHmacSHA3_256(secret []byte) Hash {
    return this.NewHmac(sha3.New256, secret)
}

// ============================================

// HmacSHA3_384 哈希值
func (this Hash) HmacSHA3_384(secret []byte) Hash {
    this.data = hmacHash(sha3.New384, this.data, secret)

    return this
}

// NewHmacSHA3_384
func (this Hash) NewHmacSHA3_384(secret []byte) Hash {
    return this.NewHmac(sha3.New384, secret)
}

// ============================================

// HmacSHA3_512 哈希值
func (this Hash) HmacSHA3_512(secret []byte) Hash {
    this.data = hmacHash(sha3.New512, this.data, secret)

    return this
}

// NewHmacSHA3_512
func (this Hash) NewHmacSHA3_512(secret []byte) Hash {
    return this.NewHmac(sha3.New512, secret)
}

// ============================================

// 签名
func hmacHash(hh func() hash.Hash, message, secret []byte) []byte {
    h := hmac.New(hh, secret)
    h.Write(message)

    return h.Sum(nil)
}
