//go:build !purego

package sm3

//go:noescape
func blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
