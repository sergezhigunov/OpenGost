using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Message Authentication Code (MAC) using <see cref="Magma"/> algorithm.
    /// </summary>
    public class MACMagma : KeyedHashAlgorithm
    {
        #region Constants

        private static readonly byte[] s_irreduciblePolynomial =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B
        };

        #endregion

        private readonly MACAlgorithm _mac;

        /// <summary>
        /// Initializes a new instance of the <see cref="MACMagma"/> class.
        /// </summary>
        public MACMagma()
            : this(GenerateRandomBytes(32))
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
            : this(MagmaManagedAlgorithmFullName, rgbKey)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACMagma"/> class with the specified key data
        /// and using the specified implementation of <see cref="Magma"/>.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the <see cref="Magma"/> implementation to use. 
        /// </param>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACMagma"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACMagma(string algorithmName, byte[] rgbKey)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));

            Magma magma =
                algorithmName == null ?
                Magma.Create() :
                Magma.Create(algorithmName);

            _mac = new MACAlgorithm(magma, rgbKey, s_irreduciblePolynomial);
        }

        /// <summary>
        /// Initializes an instance of <see cref="MACMagma"/>.
        /// </summary>
        public override void Initialize()
            => _mac.Initialize();

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
            => _mac.TransformBlock(data, dataOffset, dataSize, null, 0);

        /// <summary>
        /// Returns the computed Message Authentication Code (MAC) after all data is written to the object.
        /// </summary>
        /// <returns>
        /// The computed MAC.
        /// </returns>
        protected override byte[] HashFinal()
        {
            _mac.TransformFinalBlock(new byte[0], 0, 0);
            return _mac.Hash;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="MACGrasshopper"/>
        /// and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// true to release both managed and unmanaged resources;
        /// false to release only unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _mac.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}