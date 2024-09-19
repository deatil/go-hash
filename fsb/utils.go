package fsb

import (
    "encoding/binary"
)

// Convert a byte slice to a uint slice
func bytesToUints(b []byte) []uint {
    size := len(b) / 4
    dst := make([]uint, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = uint(binary.BigEndian.Uint32(b[j:]))
    }

    return dst
}

// Convert a uint slice to a byte slice
func uintsToBytes(w []uint) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.BigEndian.PutUint32(dst[j:], uint32(w[i]))
    }

    return dst
}

func LUI(a uint) int {
    // return int(a - 1) / (4 << 3) + 1
    return int(a - 1) / 3 + 1
}

func logarithm(a uint) int {
    var i int
    for i = 0; i < 32; i++ {
        if a == uint(1 << i) {
            return i
        }
    }

    return -1
}



