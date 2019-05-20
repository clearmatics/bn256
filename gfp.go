package bn256

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"math/big"
)

// FpUint64Size is the number of uint64 chunks to represent a field element
const FpUint64Size = 4

type gfP [FpUint64Size]uint64

func newGFp(x int64) (out *gfP) {
	if x >= 0 {
		out = &gfP{uint64(x)}
	} else {
		out = &gfP{uint64(-x)}
		gfpNeg(out, out)
	}

	montEncode(out, out)
	return out
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

// Convert a big.Int into gfP
func newGFpFromBigInt(in *big.Int) (out *gfP) {
	inBytes := in.Bytes()
	// TODO: Add assertion to test the size of the byte array
	// and make sure I have something of 256bits or less (can add a padding if needed)

	out = &gfP{}
	var n uint64
	for i := 0; i < FpUint64Size; i++ {
		buf := bytes.NewBuffer(inBytes[i*8 : (i+1)*8])
		binary.Read(buf, binary.BigEndian, &n)
		out[(FpUint64Size-1)-i] = n // In gfP field elements are represented as little-endian 64-bit words
	}

	return out
}

// Convert a gfP into a big.Int
func (e *gfP) gFpToBigInt() (out *big.Int) {
	str := e.String()

	out = new(big.Int)
	_, ok := out.SetString(str, 16)
	if !ok {
		errors.New("couldn't create big.Int from gfP element")
	}

	return out
}

func (e *gfP) Set(f *gfP) {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]
}

func (e *gfP) Invert(f *gfP) {
	// Bits is set with the value of p2 in the constants.go file
	// TODO: Remove this assigment and replace it with the p2 constant
	// var p2 = [4]uint64{0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029}
	bits := [4]uint64{0x3c208c16d87cfd45, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029}

	sum, power := &gfP{}, &gfP{}
	sum.Set(rN1)
	power.Set(f)

	for word := 0; word < 4; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				gfpMul(sum, sum, power)
			}
			gfpMul(power, power, power)
		}
	}

	gfpMul(sum, sum, r3)
	e.Set(sum)
}

func (e *gfP) Marshal(out []byte) {
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			out[8*w+b] = byte(e[3-w] >> (56 - 8*b))
		}
	}
}

func (e *gfP) Unmarshal(in []byte) error {
	// Unmarshal the bytes into little endian form
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			e[3-w] += uint64(in[8*w+b]) << (56 - 8*b)
		}
	}
	// Ensure the point respects the curve modulus
	for i := 3; i >= 0; i-- {
		if e[i] < p2[i] {
			return nil
		}
		if e[i] > p2[i] {
			return errors.New("bn256: coordinate exceeds modulus")
		}
	}
	return errors.New("bn256: coordinate equals modulus")
}

// In Montgomery representation, an element x is represented by xR mod p, where
// R is a power of 2 corresponding to the number of machine-words that can contain p.
// (where p is the characteristic of the prime field we work over)
func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpMul(c, a, &gfP{1}) }
