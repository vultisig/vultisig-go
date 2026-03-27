package address

import (
	"encoding/binary"
	"math/bits"
)

// ripemd160Sum computes RIPEMD-160 hash of data.
func ripemd160Sum(data []byte) [20]byte {
	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

	msgLen := len(data)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0x00)
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(msgLen)*8)
	data = append(data, lenBuf[:]...)

	for offset := 0; offset < len(data); offset += 64 {
		var x [16]uint32
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(data[offset+i*4:])
		}

		al, bl, cl, dl, el := h0, h1, h2, h3, h4
		ar, br, cr, dr, er := h0, h1, h2, h3, h4

		for i := 0; i < 80; i++ {
			var f, k uint32
			r, s := ripemdRL[i], ripemdSL[i]
			switch {
			case i < 16:
				f = bl ^ cl ^ dl
			case i < 32:
				f = (bl & cl) | (^bl & dl)
				k = 0x5A827999
			case i < 48:
				f = (bl | ^cl) ^ dl
				k = 0x6ED9EBA1
			case i < 64:
				f = (bl & dl) | (cl & ^dl)
				k = 0x8F1BBCDC
			default:
				f = bl ^ (cl | ^dl)
				k = 0xA953FD4E
			}
			t := bits.RotateLeft32(al+f+x[r]+k, s) + el
			al, el, dl, cl, bl = el, dl, bits.RotateLeft32(cl, 10), bl, t
		}

		for i := 0; i < 80; i++ {
			var f, k uint32
			r, s := ripemdRR[i], ripemdSR[i]
			switch {
			case i < 16:
				f = br ^ (cr | ^dr)
				k = 0x50A28BE6
			case i < 32:
				f = (br & dr) | (cr & ^dr)
				k = 0x5C4DD124
			case i < 48:
				f = (br | ^cr) ^ dr
				k = 0x6D703EF3
			case i < 64:
				f = (br & cr) | (^br & dr)
				k = 0x7A6D76E9
			default:
				f = br ^ cr ^ dr
			}
			t := bits.RotateLeft32(ar+f+x[r]+k, s) + er
			ar, er, dr, cr, br = er, dr, bits.RotateLeft32(cr, 10), br, t
		}

		t := h1 + cl + dr
		h1 = h2 + dl + er
		h2 = h3 + el + ar
		h3 = h4 + al + br
		h4 = h0 + bl + cr
		h0 = t
	}

	var digest [20]byte
	binary.LittleEndian.PutUint32(digest[0:], h0)
	binary.LittleEndian.PutUint32(digest[4:], h1)
	binary.LittleEndian.PutUint32(digest[8:], h2)
	binary.LittleEndian.PutUint32(digest[12:], h3)
	binary.LittleEndian.PutUint32(digest[16:], h4)
	return digest
}

var ripemdRL = [80]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}
var ripemdRR = [80]int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}
var ripemdSL = [80]int{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}
var ripemdSR = [80]int{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}
