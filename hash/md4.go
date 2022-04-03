package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/md4"
)

// MD4 哈希值
func MD4(s string) string {
    m := md4.New()
    m.Write([]byte(s))
    return hex.EncodeToString(m.Sum(nil))
}

// MD4 哈希值
func (this Hash) MD4() Hash {
    return this.UseHash(md4.New)
}
