# BN256

[![Build Status](https://travis-ci.org/clearmatics/bn256.svg?branch=ci)](https://travis-ci.org/clearmatics/bn256)

bn256 implements a particular bilinear group at the 128-bit security level. 

Imported from https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256

## Installation

    go get github.com/clearmatics/bn256

## Development

Dependencies are managed via [dep][1]. Dependencies are checked into this repository in the `vendor` folder. Documentation for managing dependencies is available in the [dep README][2].

The project follows standard Go conventions using `gofmt`. If you wish to contribute to the project please follow standard Go conventions. The CI server automatically runs these checks.

[1]: https://github.com/golang/dep
[2]: https://github.com/golang/dep/blob/master/README.md

