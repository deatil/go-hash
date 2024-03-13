package pmac

import (
    "fmt"
    "testing"
    "crypto/aes"
)

func Test_Check(t *testing.T) {
    key := []byte("test1235test1235")
    in := []byte("nonce-asdfg")
    check := "8d7c222273ad1056e005f9edddfca276"

    block, err := aes.NewCipher(key)
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
