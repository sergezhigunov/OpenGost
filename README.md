# Gost
This repository stores unoffical .Net implementation of modern Russian national standard cryptographic algorithms

## Features
List of supported cryptographic algoritnms
* Streebog hash algorithm (GOST R 34.11-2012)
* Grasshopper block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)
* Magma block cipher algorithm (GOST R 34.12-2015, GOST R 34.13-2015)

## References
* [GOST R 34.11-2012 "Information technology. Cryptographic data security. Hash function"](http://tc26.ru/en/standard/gost/GOST_R_34_11-2012_eng.pdf)
* [GOST R 34.12-2015 "Information technology. Cryptographic data security. Block ciphers"](http://tc26.ru/en/standard/gost/GOST_R_34_12_2015_ENG.pdf)
* [GOST R 34.13-2015 "Information technology. Cryptographic data security. Modes of operation for block ciphers"](http://tc26.ru/en/standard/gost/GOST_R_34_13_2015_ENG.pdf)

## Before the use
Before the use you have to merge the target host .Net v4.0.30319 machine.config's with the [Crypto.config](./tools/Crypto.config).
