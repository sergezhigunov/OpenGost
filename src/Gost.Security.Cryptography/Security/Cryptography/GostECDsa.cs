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

        /// <summary>
        /// When overridden in a derived class, generates a new public/private key pair for the specified curve.
        /// </summary>
        /// <param name="curve">
        /// The curve to use.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="curve"/> is invalid.
        /// </exception>
        public abstract void GenerateKey(ECCurve curve);

        /// <summary>
        /// When overridden in a derived class, exports the <see cref="ECParameters"/> for an <see cref="ECCurve"/>.
        /// </summary>
        /// <param name="includePrivateParameters">
        /// <c>true</c> to include private parameters;
        /// otherwise, <c>false</c>.</param>
        /// <returns>
        /// An <see cref="ECParameters"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// The key cannot be exported. 
        /// </exception>
        public abstract ECParameters ExportParameters(bool includePrivateParameters);

        /// <summary>
        /// When overridden in a derived class, imports the specified <see cref="ECParameters"/>.
        /// </summary>
        /// <param name="parameters">
        /// The curve parameters.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="parameters"/> are invalid.
        /// </exception>
        public abstract void ImportParameters(ECParameters parameters);


        /// <summary>
        /// Reconstructs a <see cref="GostECDsa"/> object from an XML string.
        /// </summary>
        /// <param name="xmlString">
        /// The XML string to use to reconstruct the <see cref="GostECDsa"/> object.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="xmlString"/> parameter is <c>null</c>. 
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The format of the <paramref name="xmlString"/> parameter is not valid. 
        /// </exception>
        public sealed override void FromXmlString(string xmlString)
        {
            if (xmlString == null) throw new ArgumentNullException(nameof(xmlString));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates and returns an XML string representation of the current
        /// <see cref="GostECDsa"/> object.
        /// </summary>
        /// <param name="includePrivateParameters">
        /// <c>true</c> to include private parameters; otherwise, <c>false</c>. 
        /// </param>
        /// <returns>
        /// An XML string encoding of the current <see cref="GostECDsa"/> object.
        /// </returns>
        public sealed override string ToXmlString(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }
    }
}