package pmac64

import (
    "fmt"
    "testing"
    "crypto/des"
)

func Test_Check(t *testing.T) {
    key := []byte("test1235")
    in := []byte("nonce-asdfg")
    check := "40b82d71e4d30a9d"

    block, err := des.NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    h := New(block)
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
