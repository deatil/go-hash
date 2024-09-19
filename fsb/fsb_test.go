package fsb

import (
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Hash(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}
