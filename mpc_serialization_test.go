package bn256

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestEncodeCompressed(t *testing.T) {
	_, GaInit, err := RandomG1(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Affine form of GaInit (Which is in Jacobian by default)
	GaAffine := new(G1)
	GaAffine.Set(GaInit)
	GaAffine.p.MakeAffine()

	// Get 2 copies of Ga
	GaCopy1 := new(G1)
	GaCopy1.Set(GaInit)

	GaCopy2 := new(G1)
	GaCopy2.Set(GaInit)

	// Encode GaCopy1 with the EncodeCompress function
	compressed := GaCopy1.EncodeCompressed()

	fieldOne := *newGFp(1)
	fmt.Printf("[Test] Field one = %#x\n", fieldOne)

	// Encode GaCopy2 with the Marshal function
	marshalled := GaCopy2.Marshal() // Careful Marshal modifies the point since it makes it an affine point!!

	// Make sure that the x-coordinate is encoded as it is when we call the Marshal function
	var errStr string
	if !bytes.Equal(compressed[1:], marshalled[:32]) {
		errStr = fmt.Sprintf("[Error] The EncodeCompressed and Marshal function yield different results for the x-coordinate (Marshal -> %#x; EncodeCompressed -> %#x)", marshalled[:32], compressed[1:])
		t.Fatal(errStr)
	} else {
		t.Log("bytes are equal for the x-coordinate")
	}

	// Unmarshal the point Ga with the unmarshal function
	Gb1 := new(G1)
	_, err = Gb1.Unmarshal(marshalled)
	if err != nil {
		t.Fatal(err)
	}
	// test to encode the point in jacobian coordinates because it is returned in the affine form
	// The points are encoded in the affine form, so if we want to assert the result obtained with the
	// point initially created - ie: GaInit, then we need to transform the affine coordinates into
	// jacobian by multiplyong by the same Z coordinate as GaInit!
	// Here, we assert the result against the GaAffine point which is the affine transform of GaInit
	/*
		z := &gfP{}
		z.Set(&GaInit.p.z)
		z2, z3 := &gfP{}, &gfP{}
		gfpMul(z2, z, z)
		gfpMul(z3, z2, z)
		gfpMul(&Gb1.p.x, &Gb1.p.x, z2)
		gfpMul(&Gb1.p.y, &Gb1.p.y, z3)
	*/
	if (GaAffine.p.x != Gb1.p.x) && (GaAffine.p.y != Gb1.p.y) {
		errStr = fmt.Sprintf("[Error] The Unmarshal function does not retreive original point (unmarshal -> (%#x, %#x); initial point -> (%#x, %#x))", Gb1.p.x, Gb1.p.y, GaInit.p.x, GaInit.p.y)
		t.Fatal(errStr)
	} else {
		t.Log("Successfully unmarshalled point")
	}

	// Decode the point Ga with the decodeCompress function
	Gb2 := new(G1)
	err = Gb2.DecodeCompressed(compressed)
	if err != nil {
		t.Fatal(err)
	}

	if (GaAffine.p.x != Gb2.p.x) && (GaAffine.p.y != Gb2.p.y) {
		errStr = fmt.Sprintf("[Error] The DecodeCompressed function does not retreive the original point (decodeCompressed -> (%#x, %#x); initial point -> (%#x, %#x))", Gb2.p.x, Gb2.p.y, GaInit.p.x, GaInit.p.y)
		t.Fatal(errStr)
	} else {
		t.Log("Successfully decompressed point")
	}
}

func TestIsHigherY(t *testing.T) {
	_, Ga, err := RandomG1(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	Ga.p.MakeAffine()

	GaNeg := new(G1)
	GaNeg.Neg(Ga)
	GaNeg.p.MakeAffine()

	// Verify that Ga.p.y + GaNeg.p.y == 0
	SumYs := &gfP{}
	zero := newGFp(0)
	gfpAdd(SumYs, &Ga.p.y, &GaNeg.p.y)
	if *SumYs != *zero {
		t.Fatalf("The y-coordinates should add up to zero... (Have: %#x, %#x, %#x, %#x)", SumYs[3], SumYs[2], SumYs[1], SumYs[0])
	} else {
		t.Log("The y-coordinates add up to 0, which is the expected behavior")
	}

	// Find which point between Ga and GaNeg is the one witht eh higher Y
	res := gfpComp(&GaNeg.p.y, &Ga.p.y)
	if res > 0 { // GaNeg.p.y > Ga.p.y
		if GaNeg.IsHigherY() {
			t.Log("GaNeg has the higher Y which is expected")
		} else {
			t.Fatal("GaNeg should have the higherY")
		}
	} else if res < 0 { // GaNeg.p.y < Ga.p.y
		if Ga.IsHigherY() {
			t.Log("Ga has the higher Y which is expected")
		} else {
			t.Fatal("Ga should have the higherY")
		}
	}
}
