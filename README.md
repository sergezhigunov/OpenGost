# Gost

This repository stores unoffical .Net implementation of modern Russian national standard cryptographic algorithms


## Supported Algorithms

* 512 and 256 bits Streebog hash algorithm (GOST R 34.11-2012)
* 512 and 256 bits HMAC Streebog (Hash-based Message Authentification Code)
* Grasshopper block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)
* CMAC Grasshopper (Cipher-based Message Authentification Code algorithm)
* Magma block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)
* CMAC Magma (Cipher-based Message Authentification Code algorithm)


## Algorithms in Development

* GOST Elliptic Curve Digital Signature Algorithm (GOST R 34.10-2012)


## References

* [GOST R 34.10-2012 "Digital Signature Algorithm"](https://tools.ietf.org/html/rfc7091)
* [GOST R 34.11-2012 "Information technology. Cryptographic data security. Hash function"](http://tc26.ru/en/standard/gost/GOST_R_34_11-2012_eng.pdf)
* [GOST R 34.12-2015 "Information technology. Cryptographic data security. Block ciphers"](http://tc26.ru/en/standard/gost/GOST_R_34_12_2015_ENG.pdf)
* [GOST R 34.13-2015 "Information technology. Cryptographic data security. Modes of operation for block ciphers"](http://tc26.ru/en/standard/gost/GOST_R_34_13_2015_ENG.pdf)


## Before the use

Before the use you have to merge the target host .Net v4.0.30319 machine.config's with the [Crypto.config](./tools/Crypto.config).

