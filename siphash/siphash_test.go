package siphash

import (
    "bytes"
    "testing"
)

func Test_Hash(t *testing.T) {
    key := []byte("1234567812345678")
    data := []byte("test data")

    h := New(key)
    h.Write(data)
    res := h.Sum(nil)

    if len(res) == 0 {
        t.Error("Hash error")
    }
}

func test_Check(t *testing.T) {
    var key [KEY_SIZE]byte
    var in []byte
    var i int

    expected := []byte{ 0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f, }

    for i = 0; i < KEY_SIZE; i++ {
        key[i] = byte(i)
    }

    inlen := 16
    in = make([]byte, inlen)
    for i = 0; i < inlen; i++ {
        in[i] = byte(i)
    }

    h := NewWithCDroundsAndHashSize(key[:], 0, 0, 8)
    h.Write(in[:])
    res := h.Sum(nil)

    if !bytes.Equal(expected, res) {
        t.Error("Check Hash error")
    }
}
