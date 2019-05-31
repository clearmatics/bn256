package bn256

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestG2DecodeCompressed(t *testing.T) {
	_, GaInit, err := RandomG2(rand.Reader)
	assert.NoError(t, err, "Err should be nil")

	// Affine form of GaInit
	GaAffine := new(G2)
	GaAffine.Set(GaInit)
	GaAffine.p.MakeAffine()

	// Encode GaCopy1 with the EncodeCompress function
	GaCopy1 := new(G2)
	GaCopy1.Set(GaInit)
	compressed := GaCopy1.EncodeCompressed()

	// Encode GaCopy2 with the Marshal function
	GaCopy2 := new(G2)
	GaCopy2.Set(GaInit)
	marshalled := GaCopy2.Marshal() // Careful Marshal modifies the point since it makes it an affine point!

	// Make sure that the x-coordinate is encoded as it is when we call the Marshal function
	assert.Equal(
		t,
		compressed[1:],  // Ignore the masking byte
		marshalled[:64], // Get only the x-coordinate
		"The EncodeCompressed and Marshal function yield different results for the x-coordinate",
	)

	// Unmarshal the point Ga with the unmarshal function
	Gb1 := new(G2)
	_, err = Gb1.Unmarshal(marshalled)
	assert.Nil(t, err)
	assert.Equal(t, GaAffine.p.x.String(), Gb1.p.x.String(), "The x-coord of the unmarshalled point should equal the x-coord of the intial point")
	assert.Equal(t, GaAffine.p.y.String(), Gb1.p.y.String(), "The y-coord of the unmarshalled point should equal the y-coord of the intial point")

	// Decode the point Ga with the decodeCompress function
	Gb2 := new(G2)
	err = Gb2.DecodeCompressed(compressed)
	assert.Nil(t, err)
	assert.Equal(t, GaAffine.p.x.String(), Gb2.p.x.String(), "The x-coord of the decompressed point should equal the x-coord of the intial point")
	assert.Equal(t, GaAffine.p.y.String(), Gb2.p.y.String(), "The y-coord of the decompressed point should equal the y-coord of the intial point")
}
