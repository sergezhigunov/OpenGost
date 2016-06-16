using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Provides a managed implementation of the <see cref="GostECDsa"/> algorithm. 
    /// </summary>
    public sealed class GostECDsaManaged : GostECDsa
    {
        private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(256, 512, 256) };

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
        /// with a random key pair.
        /// </summary>
        public GostECDsaManaged()
            : this(512)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
        /// with a random key pair, using the specified key size.
        /// </summary>
        /// <param name="keySize">
        /// The size of the key. Valid key sizes are 256 and 512 bits.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="keySize"/> specifies an invalid length.
        /// </exception>
        public GostECDsaManaged(int keySize)
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySize = keySize;

            throw new NotImplementedException();
        }

        /// <summary>
        /// Generates a digital signature for the specified hash value.
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
        public override byte[] SignHash(byte[] hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Verifies a digital signature against the specified hash value. 
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
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (signature == null) throw new ArgumentNullException(nameof(signature));

            throw new NotImplementedException();
        }
    }
}