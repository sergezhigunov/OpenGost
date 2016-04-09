using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    /// <summary>
    /// Computes a Message Authentication Code (MAC) using <see cref="Magma"/>
    /// for the input data <see cref="CryptoStream"/>.
    /// </summary>
    public class MACMagma : KeyedHashAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MACMagma"/> class.
        /// </summary>
        public MACMagma()
            : this(GenerateRandomBytes(64))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACMagma"/> class with the specified key data.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACMagma"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACMagma(byte[] rgbKey)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes an instance of <see cref="MACMagma"/>.
        /// </summary>
        public override void Initialize()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Routes data written to the object into the <see cref="Magma"/>
        /// encryptor for computing the Message Authentication Code (MAC).
        /// </summary>
        /// <param name="data">
        /// The input data.
        /// </param>
        /// <param name="dataOffset">
        /// The offset into the byte array from which to begin using data.
        /// </param>
        /// <param name="dataSize">
        /// The number of bytes in the array to use as data.
        /// </param>
        protected override void HashCore(byte[] data, int dataOffset, int dataSize)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the computed Message Authentication Code (MAC) after all data is written to the object.
        /// </summary>
        /// <returns>
        /// The computed MAC.
        /// </returns>
        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }
    }
}
