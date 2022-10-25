# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to the following versioning pattern:

Given a version number MAJOR.MINOR.PATCH, increment:

- MAJOR version when **breaking changes** are introduced;
- MINOR version when **backwards compatible changes** are introduced;
- PATCH version when backwards compatible bug **fixes** are implemented.


## [Unreleased]
### Changed
- internal structure to use native ruby logic instead of openssl
### Added
- EllipticCurve::Curve.add() function to dynamically add curves to the library
- EllipticCurve::PublicKey.toCompressed() function to dump a public key in compressed format
- EllipticCurve::PublicKey.fromCompressed() function to read a public key in compressed format

## [0.0.5] - 2020-06-23
### Added
- first official version based on OpenSSL
