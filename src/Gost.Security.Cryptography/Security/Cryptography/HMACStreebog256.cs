using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC)
    /// by using the <see cref="Streebog256"/> hash function.
    /// </summary>
    public class HMACStreebog256 : HMAC
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HMACStreebog256"/>
        /// class with a randomly generated key.
        /// </summary>
        public HMACStreebog256()
            : this(GenerateRandomBytes(64))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="HMACStreebog256"/>
        /// class with the specified key data.
        /// </summary>
        /// <param name="key">
        /// The secret key for <see cref="HMACStreebog256"/> encryption.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is null. 
        /// </exception>
        public HMACStreebog256(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            HashSizeValue = 256;
            HashName = Streebog256AlgorithmName;
            base.Key = key;
        }
    }
}
