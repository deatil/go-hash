//go:build !purego

package sm3

//go:noescape
func transposeMatrix8x8(dig **[8]uint32)

//go:noescape
func blockMultBy8(dig **[8]uint32, p *[]byte, buffer *byte, blocks int)
