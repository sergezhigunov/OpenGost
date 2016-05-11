using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;

    /// <summary>
    /// Provides an abstract base class that encapsulates the GOST
    /// Elliptic Curve Digital Signature Algorithm (GOST R 34.10-2012).
    /// </summary>
    public abstract class GostECDsa : AsymmetricAlgorithm
    {
        /// <summary>
        /// Gets the name of the key exchange algorithm.
        /// </summary>
        /// <value>
        /// Always <c>null</c>.
        /// </value>
        public override string KeyExchangeAlgorithm => null;

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        /// <value>
        /// Always <c>"GostECDsa"</c>.
        /// </value>
        public override string SignatureAlgorithm => GostECDsaAlgorithmName;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa"/> class.
        /// </summary>
        protected GostECDsa()
        { }

        /// <summary>
        /// When overridden in a derived class, generates a digital signature
        /// for the specified hash value.
        /// </summary>
        /// <param name="hash">
        /// The hash value of the data that is being signed.
        /// </param>
        /// <returns>
        /// A digital signature that consists of the given hash value encrypted with the private key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="hash"/> parameter is <c>null</c>.
        /// </exception>
        public abstract byte[] SignHash(byte[] hash);

        /// <summary>
        /// When overridden in a derived class, verifies a digital signature
        /// against the specified hash value. 
        /// </summary>
        /// <param name="hash">
        /// The hash value of a block of data.
        /// </param>
        /// <param name="signature">
        /// The digital signature to be verified.
        /// </param>
        /// <returns>
        /// <c>true</c> if the hash value equals the decrypted signature;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="hash"/> parameter is <c>null</c>.
        /// -or-
        /// The <paramref name="signature"/> parameter is <c>null</c>.
        /// </exception>
        public abstract bool VerifyHash(byte[] hash, byte[] signature);
    }
}