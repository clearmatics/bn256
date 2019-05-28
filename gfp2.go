package bn256

import (
	"math"
	"math/big"
)

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-1.
type gfP2 struct {
	x, y gfP // value is xi+y.
}

func gfP2Decode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montDecode(&out.x, &in.x)
	montDecode(&out.y, &in.y)
	return out
}

func (e *gfP2) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x = gfP{0}
	e.y = gfP{0}
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x = gfP{0}
	e.y = *newGFp(1)
	return e
}

func (e *gfP2) IsZero() bool {
	zero := gfP{0}
	return e.x == zero && e.y == zero
}

func (e *gfP2) IsOne() bool {
	zero, one := gfP{0}, *newGFp(1)
	return e.x == zero && e.y == one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(&a.y)
	gfpNeg(&e.x, &a.x)
	return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
	gfpNeg(&e.x, &a.x)
	gfpNeg(&e.y, &a.y)
	return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &b.x)
	gfpAdd(&e.y, &a.y, &b.y)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	gfpSub(&e.x, &a.x, &b.x)
	gfpSub(&e.y, &a.y, &b.y)
	return e
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf Section 3 "Schoolbook method"
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	tx, t := &gfP{}, &gfP{}
	gfpMul(tx, &a.x, &b.y) // tx = a.x * b.y
	gfpMul(t, &b.x, &a.y)  // t = b.x * a.y
	gfpAdd(tx, tx, t)      // tx = a.x * b.y + b.x * a.y

	ty := &gfP{}
	gfpMul(ty, &a.y, &b.y) // ty = a.y * b.y
	gfpMul(t, &a.x, &b.x)  // t = a.x * b.x
	// We do a subtraction in the field since β = -1 in our case
	// In fact, Fp2 is built using the irreducible polynomial X^2 - β, where β = -1 = p-1
	gfpSub(ty, ty, t) // ty = a.y * b.y - a.x * b.x

	e.x.Set(tx) // e.x = a.x * b.y + b.x * a.y
	e.y.Set(ty) // e.y = a.y * b.y - a.x * b.x
	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
	gfpMul(&e.x, &a.x, b)
	gfpMul(&e.y, &a.y, b)
	return e
}

// MulXi sets e=ξa where ξ=i+9 and then returns e.
func (e *gfP2) MulXi(a *gfP2) *gfP2 {
	// (xi+y)(i+9) = (9x+y)i+(9y-x)
	tx := &gfP{}
	gfpAdd(tx, &a.x, &a.x)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, &a.x)

	gfpAdd(tx, tx, &a.y)

	ty := &gfP{}
	gfpAdd(ty, &a.y, &a.y)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, &a.y)

	gfpSub(ty, ty, &a.x)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xi+y)² = (x+y)(y-x) + 2*i*x*y
	tx, ty := &gfP{}, &gfP{}
	gfpSub(tx, &a.y, &a.x)
	gfpAdd(ty, &a.x, &a.y)
	gfpMul(ty, tx, ty)

	gfpMul(tx, &a.x, &a.y)
	gfpAdd(tx, tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2 := &gfP{}, &gfP{}
	gfpMul(t1, &a.x, &a.x)
	gfpMul(t2, &a.y, &a.y)
	gfpAdd(t1, t1, t2)

	inv := &gfP{}
	inv.Invert(t1)

	gfpNeg(t1, &a.x)

	gfpMul(&e.x, t1, inv)
	gfpMul(&e.y, &a.y, inv)
	return e
}

// Exp is a function to exponentiate field elements
// This function navigates the big int binary representation (assumed to be in big endian)
// from left to right.
// When going from left to right, each bit is checked, and when the first `1` bit is found
// the `foundOne` flag is set, and the "exponentiation begins"
//
// Eg: Let's assume that we want to exponentiate 3^5
// then the exponent is 5 = 0000 0101
// We navigate 0000 0101 from left to right until we reach 0000 0101
//                                                               ^
//                                                               |
// When this bit is reached, the flag `foundOne` is set, and and we do:
// res = res * 3 = 3
// Then, we move on to the left to read the next bit, and since `foundOne` is set (ie:
// the exponentiation has started), then we square the result, and do:
// res = res * res = 3*3 = 3^2
// The bit is `0`, so we continue
// Next bit is `1`, so we do: res = res * res = 3^2 * 3^2 = 3^4
// and because the bit is `1`, then, we do res = res * 3 = 3^4 * 3 = 3^5
// We reached the end of the bit string, so we can stop.
//
// The binary representation of the exponent is assumed to be binary big endian
//
// Careful, since `res` is initialized with SetOne() and since this function
// initializes the calling gfP2 to the one element of the Gfp2 which is montEncoded
// then, we need to make sure that the `e` element of gfP2 used to call the Exp function
// is also montEncoded (ie; both x and y are montEncoded)
func (e *gfP2) Exp(exponent *big.Int) *gfP2 {
	res := &gfP2{}
	res = res.SetOne()

	base := &gfP2{}
	base = base.Set(e)

	foundOne := false
	// Absolute value of `exponent` as a big-endian Byte slice
	exponentBytes := exponent.Bytes() // big endian bytes slice

	for i := 0; i < len(exponentBytes); i++ { // for each byte (remember the slice is big endian)
		for j := 0; j <= 7; j++ { // A byte contains the powers of 2 to 2^7 to 2^0 from left to right
			if foundOne {
				res = res.Mul(res, res)
			}

			if uint(exponentBytes[i])&uint(math.Pow(2, float64(7-j))) != uint(0) { // a byte contains the powers of 2 from 2^7 to 2^0 hence why we do 2^(7-j)
				foundOne = true
				res = res.Mul(res, base)
			}
		}
	}

	e.Set(res)
	return e
}
