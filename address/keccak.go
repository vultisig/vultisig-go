package address

// Pure Go Keccak-256 implementation (FIPS 202 / SHA-3 variant used by Ethereum)

const keccakRounds = 24

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRotc = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var keccakPiln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

func keccakF1600(st *[25]uint64) {
	var t uint64
	var bc [5]uint64

	for round := 0; round < keccakRounds; round++ {
		// Theta
		for i := 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := 0; i < 5; i++ {
			t = bc[(i+4)%5] ^ (bc[(i+1)%5]<<1 | bc[(i+1)%5]>>63)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}

		// Rho Pi
		t = st[1]
		for i := 0; i < 24; i++ {
			j := keccakPiln[i]
			bc[0] = st[j]
			st[j] = t<<keccakRotc[i] | t>>(64-keccakRotc[i])
			t = bc[0]
		}

		// Chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}

		// Iota
		st[0] ^= keccakRC[round]
	}
}

// keccak256 computes the Keccak-256 hash (NOT SHA3-256, which differs in padding).
func keccak256(data []byte) [32]byte {
	const rate = 136 // (1600 - 256*2) / 8

	var st [25]uint64

	// Absorb
	offset := 0
	for offset+rate <= len(data) {
		for i := 0; i < rate/8; i++ {
			st[i] ^= le64(data[offset+i*8:])
		}
		keccakF1600(&st)
		offset += rate
	}

	// Pad
	remaining := len(data) - offset
	buf := make([]byte, rate)
	copy(buf, data[offset:])
	buf[remaining] = 0x01 // Keccak padding (NOT 0x06 which is SHA3)
	buf[rate-1] |= 0x80

	for i := 0; i < rate/8; i++ {
		st[i] ^= le64(buf[i*8:])
	}
	keccakF1600(&st)

	// Squeeze
	var hash [32]byte
	for i := 0; i < 4; i++ {
		putLe64(hash[i*8:], st[i])
	}
	return hash
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func putLe64(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}
