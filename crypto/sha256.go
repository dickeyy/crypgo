package crypto

import bitwise "github.com/dickeyy/crypgo/utils"

// constatnts for sha256
var k = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// initial values ofr sha256
var h0 = []uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// sha256 algorithm
func SHA256(message []byte) []byte {
	// Preprocessing
	paddedMessage := padMessage(message)
	blocks := createBlocks(paddedMessage)

	// Initialize hash values
	h := make([]uint32, 8)
	copy(h, h0)

	// Process each 512-bit block
	for _, block := range blocks {
		w := createMessageSchedule(block)

		// Create working variables
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]
		e := h[4]
		f := h[5]
		g := h[6]
		hh := h[7] // renamed to hh to avoid confusion

		// Main loop
		for t := 0; t < 64; t++ {
			t1 := hh + bitwise.Sigma1(e) + bitwise.Ch(e, f, g) + k[t] + w[t]
			t2 := bitwise.Sigma0(a) + bitwise.Maj(a, b, c)

			hh = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		// Update hash values
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
		h[5] += f
		h[6] += g
		h[7] += hh
	}

	// Final hash
	hash := make([]byte, 32)
	for i, v := range h {
		hash[i*4] = byte(v >> 24)
		hash[i*4+1] = byte(v >> 16)
		hash[i*4+2] = byte(v >> 8)
		hash[i*4+3] = byte(v)
	}

	return hash
}

// helper functions
func padMessage(message []byte) []byte {
	messageLen := len(message)
	bitLen := uint64(messageLen) * 8

	// calc padding length
	paddingLen := 64 - ((messageLen + 9) % 64)
	if paddingLen < 0 {
		paddingLen += 64
	}

	// create padded message
	padded := make([]byte, messageLen+1+paddingLen+8)
	copy(padded, message)
	padded[messageLen] = 0x80 // append 1 followed by zeros

	// appedn original message length
	for i := 0; i < 8; i++ {
		padded[len(padded)-8+i] = byte(bitLen >> uint(56-i*8))
	}

	return padded
}

func createBlocks(paddedMessage []byte) [][]byte {
	blocks := make([][]byte, len(paddedMessage)/64)
	for i := range blocks {
		blocks[i] = paddedMessage[i*64 : (i+1)*64]
	}
	return blocks
}

func createMessageSchedule(block []byte) []uint32 {
	w := make([]uint32, 64)

	// first 16 words are from the block
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}

	// extend to 64 words
	for i := 16; i < 64; i++ {
		s0 := bitwise.RightRotate(w[i-15], 7) ^ bitwise.RightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := bitwise.RightRotate(w[i-2], 17) ^ bitwise.RightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	return w
}
