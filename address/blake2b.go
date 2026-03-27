package address

import (
	"encoding/binary"
	"hash"
)

// Blake2b implementation for address derivation (supports 224, 256, and 512 bit outputs)

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var blake2bSigma = [12][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

type blake2bState struct {
	h      [8]uint64
	t      [2]uint64
	buf    [128]byte
	bufLen int
	outLen int
}

func blake2bNew(outLen int) hash.Hash {
	s := &blake2bState{outLen: outLen}
	s.h = blake2bIV
	// Parameter block: fan-out=1, depth=1, digest length
	s.h[0] ^= 0x01010000 ^ uint64(outLen)
	return s
}

func (s *blake2bState) Reset() {
	s.h = blake2bIV
	s.h[0] ^= 0x01010000 ^ uint64(s.outLen)
	s.t[0] = 0
	s.t[1] = 0
	s.bufLen = 0
}

func (s *blake2bState) Size() int      { return s.outLen }
func (s *blake2bState) BlockSize() int  { return 128 }

func (s *blake2bState) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if s.bufLen == 128 {
			s.t[0] += 128
			if s.t[0] < 128 {
				s.t[1]++
			}
			blake2bCompress(&s.h, &s.buf, s.t, false)
			s.bufLen = 0
		}
		copied := copy(s.buf[s.bufLen:], p)
		s.bufLen += copied
		p = p[copied:]
	}
	return n, nil
}

func (s *blake2bState) Sum(in []byte) []byte {
	// Clone state
	var h [8]uint64
	var buf [128]byte
	copy(h[:], s.h[:])
	copy(buf[:], s.buf[:])
	t := s.t

	t[0] += uint64(s.bufLen)
	if t[0] < uint64(s.bufLen) {
		t[1]++
	}
	// Pad remaining buffer with zeros
	for i := s.bufLen; i < 128; i++ {
		buf[i] = 0
	}
	blake2bCompress(&h, &buf, t, true)

	var out [64]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return append(in, out[:s.outLen]...)
}

func blake2bCompress(h *[8]uint64, block *[128]byte, t [2]uint64, last bool) {
	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	v := [16]uint64{
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
		blake2bIV[0], blake2bIV[1], blake2bIV[2], blake2bIV[3],
		blake2bIV[4], blake2bIV[5], blake2bIV[6], blake2bIV[7],
	}
	v[12] ^= t[0]
	v[13] ^= t[1]
	if last {
		v[14] = ^v[14]
	}

	for i := 0; i < 12; i++ {
		s := blake2bSigma[i]
		blake2bG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2bG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2bG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2bG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2bG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2bG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2bG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2bG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

func blake2bG(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] += v[b] + x
	v[d] = (v[d] ^ v[a])>>32 | (v[d]^v[a])<<32
	v[c] += v[d]
	v[b] = (v[b] ^ v[c])>>24 | (v[b]^v[c])<<40
	v[a] += v[b] + y
	v[d] = (v[d] ^ v[a])>>16 | (v[d]^v[a])<<48
	v[c] += v[d]
	v[b] = (v[b] ^ v[c])>>63 | (v[b]^v[c])<<1
}

// blake2bSum256 computes BLAKE2b-256.
func blake2bSum256(data []byte) [32]byte {
	h := blake2bNew(32)
	h.Write(data)
	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}

// blake2bSum512 computes BLAKE2b-512.
func blake2bSum512(data []byte) [64]byte {
	h := blake2bNew(64)
	h.Write(data)
	sum := h.Sum(nil)
	var out [64]byte
	copy(out[:], sum)
	return out
}
