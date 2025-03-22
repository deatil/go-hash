package hash_composition

import (
    "fmt"
    "testing"
    "crypto/sha256"
    "crypto/sha512"
)

func Test_Hash256(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New(sha256.New(), sha256.New())
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    check := "2d83eef54696c60dfc3dd8913112bfa0e5625816ce98015415847fbfa639ef28"
    res := fmt.Sprintf("%x", dst)
    if res != check {
        t.Errorf("Hash error, got %s, want %s", res, check)
    }
}

func Test_Hash512(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New(sha512.New(), sha512.New())
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }

    check := "ebf7ad4357f5066d23b19d63b67d24c2f24279685dd47ae5fa36ab9f85bb05ab3b9d2b3b7b8dccb2644b6b376822027f6cc27c8fd6c430957c8d20b112233f8d"
    res := fmt.Sprintf("%x", dst)
    if res != check {
        t.Errorf("Hash error, got %s, want %s", res, check)
    }
}
