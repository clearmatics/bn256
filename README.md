# BN256

[![Build Status](https://travis-ci.org/clearmatics/bn256.svg?branch=master)](https://travis-ci.org/clearmatics/bn256)

This package implements a [particular](https://eprint.iacr.org/2013/507.pdf) bilinear group.
The code is imported from https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare

:rotating_light: **WARNING** This package originally claimed to operate at a 128-bit level. However, [recent work](https://ellipticnews.wordpress.com/2016/05/02/kim-barbulescu-variant-of-the-number-field-sieve-to-compute-discrete-logarithms-in-finite-fields/) suggest that **this is no longer the case**.

## A note on the selection of the bilinear group

The parameters defined in the `constants.go` file follow the parameters used in [alt-bn128 (libff)](https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp). These parameters were selected so that `r−1` has a high 2-adic order. This is key to improve efficiency of the key and proof generation algorithms of the SNARK used.

## Installation

    go get github.com/clearmatics/bn256

## Development

Dependencies are managed via [dep][1]. Dependencies are checked into this repository in the `vendor` folder. Documentation for managing dependencies is available in the [dep README][2].

The project follows standard Go conventions using `gofmt`. If you wish to contribute to the project please follow standard Go conventions. The CI server automatically runs these checks.

[1]: https://github.com/golang/dep
[2]: https://github.com/golang/dep/blob/master/README.md
