package bn256

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertGFpEqual(t *testing.T, a, b *gfP) {
	for i := 0; i < FpUint64Size; i++ {
		assert.Equal(t, a[i], b[i], fmt.Sprintf("The %d's elements differ between the 2 field elements", i))
	}
}

/*
func TestEncodeCompressed(t *testing.T) {
	// Create random point (Jacobian form)
	_, GaInit, err := RandomG1(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Affine form of GaInit
	GaAffine := new(G1)
	GaAffine.Set(GaInit)
	GaAffine.p.MakeAffine()

	// Encode GaCopy1 with the EncodeCompress function
	GaCopy1 := new(G1)
	GaCopy1.Set(GaInit)
	compressed := GaCopy1.EncodeCompressed()

	// Encode GaCopy2 with the Marshal function
	GaCopy2 := new(G1)
	GaCopy2.Set(GaInit)
	marshalled := GaCopy2.Marshal() // Careful Marshal modifies the point since it makes it an affine point!

	// Make sure that the x-coordinate is encoded as it is when we call the Marshal function
	assert.Equal(
		t,
		compressed[1:],  // Ignore the masking byte
		marshalled[:32], // Get only the x-coordinate
		"The EncodeCompressed and Marshal function yield different results for the x-coordinate")

	// Unmarshal the point Ga with the unmarshal function
	Gb1 := new(G1)
	_, err = Gb1.Unmarshal(marshalled)
	assert.Nil(t, err)
	assertGFpEqual(t, &GaAffine.p.x, &Gb1.p.x)
	assertGFpEqual(t, &GaAffine.p.y, &Gb1.p.y)
	//assert.Equal(t, GaAffine.p.x, Gb1.p.x, "The x-coord of the unmarshalled point should equal the x-coord of the intial point")
	//assert.Equal(t, GaAffine.p.y, Gb1.p.y, "The y-coord of the unmarshalled point should equal the y-coord of the intial point")

	// Decode the point Ga with the decodeCompress function
	Gb2 := new(G1)
	err = Gb2.DecodeCompressed(compressed)
	assert.Nil(t, err)
	assertGFpEqual(t, &GaAffine.p.x, &Gb2.p.x)
	assertGFpEqual(t, &GaAffine.p.y, &Gb2.p.y)
	//assert.Equal(t, GaAffine.p.x, Gb2.p.x, "The x-coord of the decompressed point should equal the x-coord of the intial point")
	//assert.Equal(t, GaAffine.p.y, Gb2.p.y, "The y-coord of the decompressed point should equal the y-coord of the intial point")
}
*/

func TestIsHigherY(t *testing.T) {
	_, Ga, err := RandomG1(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	Ga.p.MakeAffine()
	GaYString := Ga.p.y.String()
	GaYBig := new(big.Int)
	_, ok := GaYBig.SetString(GaYString, 16)
	assert.True(t, ok, "ok should be True")

	GaNeg := new(G1)
	GaNeg.Neg(Ga)
	GaNeg.p.MakeAffine()
	GaNegYString := GaNeg.p.y.String()
	GaNegYBig := new(big.Int)
	_, ok = GaNegYBig.SetString(GaNegYString, 16)
	assert.True(t, ok, "ok should be True")

	// Verify that Ga.p.y + GaNeg.p.y == 0
	sumYs := &gfP{}
	fieldZero := newGFp(0)
	gfpAdd(sumYs, &Ga.p.y, &GaNeg.p.y)
	assert.Equal(t, *sumYs, *fieldZero, "The y-coordinates of P and -P should add up to zero")

	// Find which point between Ga and GaNeg is the one witht eh higher Y
	res := gfpComp(&GaNeg.p.y, &Ga.p.y)
	if res > 0 { // GaNeg.p.y > Ga.p.y
		assert.True(t, GaNeg.IsHigherY(), "GaNeg.IsHigherY should be true if GaNeg.p.y > Ga.p.y")
		// Test the comparision of the big int also, should be the same result
		assert.Equal(t, GaNegYBig.Cmp(GaYBig), 1, "GaNegYBig should be bigger than GaYBig")
	} else if res < 0 { // GaNeg.p.y < Ga.p.y
		assert.False(t, GaNeg.IsHigherY(), "GaNeg.IsHigherY should be false if GaNeg.p.y < Ga.p.y")
		// Test the comparision of the big int also, should be the same result
		assert.Equal(t, GaYBig.Cmp(GaNegYBig), 1, "GaYBig should be bigger than GaNegYBig")
	}
}

func TestGetYFromX(t *testing.T) {
	// We know that the generator of the curve is P = (x: 1, y: 2, z: 1, t: 1)
	// We take x = 1 and we see if we retrieve P such that y = 2 or -P such that y' = Inv(2)
	Px := newGFp(1)
	yRetrieved, err := getYFromX(Px)
	assert.Nil(t, err)

	smallY := newGFp(2)
	fmt.Printf("Value smallY: %s\n", smallY.String())
	bigY := &gfP{}
	gfpNeg(bigY, smallY)

	testCondition := (*yRetrieved == *smallY) || (*yRetrieved == *bigY)
	assert.True(t, testCondition, "The retrieved Y should either equal 2 or Inv(2)")
}
