// Package bn256 implements a particular bilinear group at the 128-bit security
// level.
//
// Bilinear groups are the basis of many of the new cryptographic protocols that
// have been proposed over the past decade. They consist of a triplet of groups
// (G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ
// is a generator of the respective group). That function is called a pairing
// function.
//
// This package specifically implements the Optimal Ate pairing over a 256-bit
// Barreto-Naehrig curve as described in
// http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible
// with the implementation described in that paper.
package bn256

// This file implement some util functions for the MPC
// especially the serialization and deserialization functions for points in G1
import (
	"errors"
	"math/big"
)

// Constants related to the bn256 pairing friendly curve
const (
	FqElementSize      = 32
	G1CompressedSize   = FqElementSize
	G1UncompressedSize = 2 * FqElementSize
)

// https://github.com/ebfull/pairing/tree/master/src/bls12_381#serialization
// Bytes used to detect the formatting. By reading the first byte of the encoded point we can know it's nature
// ie: we can know if the point is the point at infinity, if it is encoded uncompressed or if it is encoded compressed
// Bit masking used to detect the serialization of the points and their nature
//
// The BSL12-381 curve is built over a 381-bit prime field.
// Thus each point coordinate is represented over 381 bits = 47bytes + 5bits
// Thus, to represent a point we need to have 48bytes, but the last 3 bits of the 48th byte will be set to 0
// These are these bits that are used to implement the masking, hence why the masking proposed by ebfull was:
const (
	serializationMask       = (1 << 5) - 1 // 0001 1111 // Enable to pick the 3 MSB corresponding to the serialization flag
	serializationCompressed = 1 << 7       // 1000 0000
	serializationInfinity   = 1 << 6       // 0100 0000
	serializationBigY       = 1 << 5       // 0010 0000
)

// IsHigherY is used to distinguish between the 2 points of E
// that have the same x-coordinate
// The point e is assumed to be given in the affine form
func (e *G1) IsHigherY() bool {
	yCopy := &gfP{}
	yCopy.Set(&e.p.y)

	yNeg := &gfP{}
	gfpNeg(yNeg, yCopy)

	for i := 0; i < FpUint64Size; i++ {
		if yCopy[i] > yNeg[i] {
			return true
		} else if yCopy[i] < yNeg[i] {
			return false
		}
	}

	return false
}

// EncodeCompressed converts the compressed point e into bytes
func (e *G1) EncodeCompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = G1CompressedSize

	e.p.MakeAffine()
	// The +1 accounts for the additional byte used for the flags/masks of the encoding
	ret := make([]byte, numBytes+1)

	// Flag the encoding with the compressed flag
	ret[0] |= serializationCompressed

	if e.p.IsInfinity() {
		// Flag the encoding with the infinity flag
		ret[0] |= serializationInfinity
		return ret
	}

	if e.IsHigherY() {
		// Flag the encoding with the bigY flag
		ret[0] |= serializationBigY
	}

	temp := &gfP{}

	// We start the serializagtion of the coordinates at the index 1
	// Since the index 0 in the `ret` corresponds to the masking
	montDecode(temp, &e.p.x)
	temp.Marshal(ret[1:])

	return ret
}

// EncodeUncompressed converts the compressed point e into bytes
func (e *G1) EncodeUncompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = G1UncompressedSize

	e.p.MakeAffine()
	// The +1 accounts for the additional byte used for the flags/masks of the encoding
	ret := make([]byte, numBytes+1)

	if e.p.IsInfinity() {
		// Flag the encoding with the infinity flag
		ret[0] |= serializationInfinity
		return ret
	}

	temp := &gfP{}

	// We start the serializagtion of the coordinates at the index 1
	// Since the index 0 in the `ret` corresponds to the masking
	montDecode(temp, &e.p.x)
	temp.Marshal(ret[1:])
	montDecode(temp, &e.p.y)
	temp.Marshal(ret[numBytes+1:])

	return ret
}

func getYFromX(x *gfP) *gfP {
	xBig := x.gFpToBigInt()
	curveBBig := bigFromBase10("3")               // E: y^2 = x^3 + 3
	curveExpBig := bigFromBase10("3")             // E: y^2 = x^3 + 3
	rhs := new(big.Int).Exp(xBig, curveExpBig, P) // x^3 mod p
	rhs.Add(rhs, curveBBig)                       // x^3 + 3

	// x = b^{(p+1)/4} is a solution to x^2 % p = b
	// Since Fp is such that p = 3 mod 4
	finalExpNum := new(big.Int).Add(P, bigFromBase10("1"))
	finalExp := new(big.Int).Div(finalExpNum, bigFromBase10("4"))
	yCoord := new(big.Int).Exp(rhs, finalExp, P)

	return newGFpFromBigInt(yCoord)
}

// DecodeCompressed decodes a point in the compressed form
func (e *G1) DecodeCompressed(encoding []byte) error {
	if len(encoding) != G1UncompressedSize {
		return errors.New("wrong encoded point size")
	}
	if (encoding[0]&serializationCompressed == 0) && (len(encoding) < G1UncompressedSize) { // Also test the length of the encoding to make sure it is 33bytes
		return errors.New("point isn't compressed")
	}

	// Unmarshal the points and check their caps
	if e.p == nil {
		e.p = &curvePoint{}
	} else {
		e.p.x, e.p.y = gfP{0}, gfP{0}
	}

	bin := make([]byte, G1CompressedSize+1)
	copy(bin, encoding)
	// Removes the bits of the masking (This does a bitwise AND with `0001 1111`)
	// And thus removes the first 3 bits corresponding to the masking
	bin[0] &= serializationMask

	// Decode the point at infinity in the compressed form
	if encoding[0]&serializationInfinity != 0 {
		if encoding[0]&serializationBigY != 0 {
			return errors.New("high Y bit improperly set")
		}

		// Similar to `for i:=0; i<len(bin); i++ {}`
		for i := range bin {
			if bin[i] != 0 {
				return errors.New("invalid infinity encoding")
			}
		}
		e.p.SetInfinity()
		return nil
	}

	// Decompress the point P (P =/= ∞)
	var err error
	if err = e.p.x.Unmarshal(encoding); err != nil {
		return err
	}

	// Now, to compute y from x, we leverage the fact that p = 3 mod 4
	// In fact, 21888242871839275222246405745257275088696311157297823662689037894645226208583 % 4 = 3
	// Then x = b^{(p+1)/4} is a solution to x^2 % p = b
	// see: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm for details on the Tonelli–Shanks algorithm
	// see: https://en.wikipedia.org/wiki/Cipolla%27s_algorithm for details on the Cipolla-Lehmer algorithm
	y := getYFromX(&e.p.x)
	e.p.y = *y

	montEncode(&e.p.x, &e.p.x)
	montEncode(&e.p.y, &e.p.y)

	// The flag serializationBigY is set (so the point pt with the higher Y is encoded)
	// but the point e retrieved from the `getYFromX` is NOT the higher, then we inverse
	if !e.IsHigherY() {
		if bin[0]&serializationBigY != 0 {
			e.Neg(e)
		}
	} else {
		if bin[0]&serializationBigY == 0 { // The point given by getYFromX is the higher but the mask is not set for higher y
			e.Neg(e)
		}
	}

	return nil
}
