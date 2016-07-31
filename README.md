# Gost

This repository stores unoffical .Net implementation of modern Russian national standard cryptographic algorithms


## Supported Algorithms

* 512 and 256 bits Streebog hash algorithms (GOST R 34.11-2012)
* 512 and 256 bits Streebog HMAC (Hash-based Message Authentification Code) algorithms
* Grasshopper block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)
* CMAC Grasshopper (Cipher-based Message Authentification Code algorithm)
* Magma block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)
* CMAC Magma (Cipher-based Message Authentification Code algorithm)


## Algorithms in Development

* GOST Elliptic Curve Digital Signature Algorithm (GOST R 34.10-2012)
* Pseudorandom function algorithm based on Streebog HMAC
* Key derivation function algorithm based on Streebog HMAC
* Key agreement algorithm based on GOST R 34.10-2012
* Key wrap and key unwrap algorithm
* GOST 28147-89 block cipher algorithm (non-normative, for backward compatibility, similar to Magma, but has another endianness)
* GOST R 34.11-94 Hash Function Algorithm (non-normative, for backward compatibility)


## Normative References

* [GOST R 34.11-2012](http://tc26.ru/en/standard/gost/GOST_R_34_11-2012_eng.pdf) Information technology. Cryptographic data security. Hash function
* [GOST R 34.12-2015](http://tc26.ru/en/standard/gost/GOST_R_34_12_2015_ENG.pdf) Information technology. Cryptographic data security. Block ciphers
* [GOST R 34.13-2015](http://tc26.ru/en/standard/gost/GOST_R_34_13_2015_ENG.pdf) Information technology. Cryptographic data security. Modes of operation for block ciphers
* [RFC 6986](https://tools.ietf.org/html/rfc6986) GOST R 34.11-2012: Hash Function
* [RFC 7091](https://tools.ietf.org/html/rfc7091) GOST R 34.10-2012: Digital Signature Algorithm
* [RFC 7801](https://tools.ietf.org/html/rfc7801) GOST R 34.12-2015: Block Cipher "Kuznyechik"
* [RFC 7836](https://tools.ietf.org/html/rfc7836) Guidelines on the Cryptographic Algorithms to Accompany the Usage of Standards GOST R 34.10-2012 and GOST R 34.11-2012


## Informative references

* [NIST-CMAC](http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf) NIST, Special Publication 800-38B, "Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication", May 2005.
* [RFC 2104](https://tools.ietf.org/html/rfc2104) HMAC: Keyed-Hashing for Message Authentication
* [RFC 4357](https://tools.ietf.org/html/rfc4357) Additional Cryptographic Algorithms for Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms
* [RFC 4490](https://tools.ietf.org/html/rfc4490) Using the GOST 28147-89, GOST R 34.11-94, GOST R 34.10-94, and GOST R 34.10-2001 Algorithms with Cryptographic Message Syntax (CMS)
* [RFC 4491](https://tools.ietf.org/html/rfc4491) Using the GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms with the Internet X.509 Public Key Infrastructure Certificate and CRL Profile
* [RFC 5830](https://tools.ietf.org/html/rfc5830) GOST 28147-89: Encryption, Decryption, and Message Authentication Code (MAC) Algorithms
* [RFC 5831](https://tools.ietf.org/html/rfc5831) GOST R 34.11-94: Hash Function Algorithm
* [RFC 5832](https://tools.ietf.org/html/rfc5832) GOST R 34.10-2001: Digital Signature Algorithm

