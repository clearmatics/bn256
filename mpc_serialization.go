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
	"fmt"
	"math/big"
)

// Constants related to the bn256 pairing friendly curve
const (
	FqElementSize      = 32
	G1CompressedSize   = FqElementSize + 1
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

	// TODO: Use the gfpCmp function instead of re-implementing the loop here
	for i := FpUint64Size - 1; i >= 0; i-- { // See gfpComp: We are dealing with little-endian 64-bit words!
		if yCopy[i] > yNeg[i] {
			return true
		} else if yCopy[i] < yNeg[i] {
			return false
		}
	}

	return false
}

// Util function to compare field elements. Should be defined in gfP files
// Compares 2 gfP
// Returns 1 if a > b; 0 if a == b; -1 if a < b
func gfpComp(a, b *gfP) int {
	for i := FpUint64Size - 1; i >= 0; i-- { // Remember that the gfP elements are written as little-endian 64-bit words
		if a[i] > b[i] { // As soon as we figure out that the MSByte of A > MSByte of B, we return
			return 1
		} else if a[i] == b[i] { // If the current bytes are equal we continue as we cannot conclude on A and B relation
			continue
		} else { // a[i] < b[i] so we can directly conclude and we return
			return -1
		}
	}
	return 0
}

// EncodeCompressed converts the compressed point e into bytes
func (e *G1) EncodeCompressed() []byte {
	fmt.Printf("== [EncodeCompressed - DEBUG] e.p.x: %#x\n", e.p.x)
	fmt.Printf("== [EncodeCompressed - DEBUG] e.p.y: %#x\n", e.p.y)

	e.p.MakeAffine()
	ret := make([]byte, G1CompressedSize)

	// Flag the encoding with the compressed flag
	ret[0] |= serializationCompressed

	if e.p.IsInfinity() {
		// Flag the encoding with the infinity flag
		fmt.Println("== [EncodeCompressed - DEBUG] Setting flag for infinity point")
		ret[0] |= serializationInfinity
		return ret
	}

	if e.IsHigherY() {
		// Flag the encoding with the bigY flag
		fmt.Println("== [EncodeCompressed - DEBUG] Setting flag for BigY point")
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
// Take a point P in Jacobian form (where each coordinate is MontEncoded)
// and encodes it by going back to affine coordinates and montDecode all coordinates
func (e *G1) EncodeUncompressed() []byte {

	e.p.MakeAffine()
	// The +1 accounts for the additional byte used for the flags/masks of the encoding
	ret := make([]byte, G1UncompressedSize)

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
	temp.Marshal(ret[G1CompressedSize:])

	return ret
}

// Takes a MontEncoded x and finds the corresponding y (one of the two possible y's)
func getYFromMontEncodedX(x *gfP) (*gfP, error) {
	// Operations on montgomery encoded field elements
	x2 := &gfP{}
	gfpMul(x2, x, x)

	x3 := &gfP{}
	gfpMul(x3, x2, x)

	rhs := &gfP{}
	gfpAdd(rhs, x3, curveB) // curveB is MontEncoded, since it is create with newGFp

	// Montgomery decode rhs
	// Needed because when we create a GFp element
	// with gfP{}, then it is not montEncoded. However
	// if we create an element of GFp by using `newGFp()`
	// then this field element is Montgomery encoded
	// Above, we have been working on Montgomery encoded field elements
	// here we solve the quad. resid. over F (not encoded)
	// and then we encode back and return the encoded result
	//
	// Eg:
	// - Px := &gfP{1} => 0000000000000000000000000000000000000000000000000000000000000001
	// - PxNew := newGFp(1) => 0e0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d
	montDecode(rhs, rhs)
	rhsBig := rhs.gFpToBigInt()

	// Note, if we use the ModSqrt method, we don't need the exponent, so we can comment these lines
	yCoord := big.NewInt(0)
	res := yCoord.ModSqrt(rhsBig, P)
	if res == nil {
		return nil, errors.New("not a square mod P")
	}

	yCoordGFp := newGFpFromBigInt(yCoord)
	montEncode(yCoordGFp, yCoordGFp)

	return yCoordGFp, nil
}

// DecodeCompressed decodes a point in the compressed form
// Take a point P encoded (ie: written in affine form where each coordinate is MontDecoded)
// and encodes it by going back to Jacobian coordinates and montEncode all coordinates
func (e *G1) DecodeCompressed(encoding []byte) error {
	fmt.Printf("== [DecodeCompressed - DEBUG] value of encoding input: %#x\n", encoding)
	if len(encoding) != G1CompressedSize {
		return errors.New("wrong encoded point size")
	}
	if encoding[0]&serializationCompressed == 0 { // Also test the length of the encoding to make sure it is 33bytes
		return errors.New("point isn't compressed")
	}

	// Unmarshal the points and check their caps
	if e.p == nil {
		e.p = &curvePoint{}
	} else {
		e.p.x, e.p.y = gfP{0}, gfP{0}
		e.p.z, e.p.t = *newGFp(1), *newGFp(1)
	}

	// Removes the bits of the masking (This does a bitwise AND with `0001 1111`)
	// And thus removes the first 3 bits corresponding to the masking
	// Useless for now because in bn256, we added a full byte to enable masking
	// However, this is needed if we work over BLS12 and its underlying field
	bin := make([]byte, G1CompressedSize)
	copy(bin, encoding)

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
		fmt.Println("== [DecodeCompressed - DEBUG] Setting point at infinity!!")
		e.p.SetInfinity()
		return nil
	}

	// Decompress the point P (P =/= ∞)
	var err error
	if err = e.p.x.Unmarshal(bin[1:]); err != nil {
		return err
	}

	// MontEncode our field elements for fast finite field arithmetic
	montEncode(&e.p.x, &e.p.x)
	y, err := getYFromMontEncodedX(&e.p.x)
	if err != nil {
		return err
	}
	e.p.y = *y

	// The flag serializationBigY is set (so the point pt with the higher Y is encoded)
	// but the point e retrieved from the `getYFromX` is NOT the higher, then we inverse
	if !e.IsHigherY() {
		if encoding[0]&serializationBigY != 0 {
			e.Neg(e)
		}
	} else {
		if encoding[0]&serializationBigY == 0 { // The point given by getYFromX is the higher but the mask is not set for higher y
			e.Neg(e)
		}
	}

	return nil
}
