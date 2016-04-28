using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Cipher-based Message Authentication Code (CMAC) using <see cref="Grasshopper"/> algorithm.
    /// </summary>
    public class CMACGrasshopper : KeyedHashAlgorithm
    {
        #region Constants

        private static readonly byte[] s_irreduciblePolynomial =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
        };

        #endregion

        private readonly CMACAlgorithm _cmacAlgorithm;

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <value>
        /// The size, in bits, of the computed hash code.
        /// </value>
        public override int HashSize => _cmacAlgorithm.HashSize;

        /// <summary>
        /// Gets or sets the key to use in the hash algorithm.
        /// </summary>
        /// <value>
        /// The key to use in the hash algorithm.
        /// </value>
        /// <exception cref="CryptographicException">
        /// An attempt was made to change the <see cref="Key"/>
        /// property after hashing has begun.
        /// </exception>
        public override byte[] Key
        {
            get { return _cmacAlgorithm.Key; }
            set
            {
                base.Key = value;
                _cmacAlgorithm.Key = value;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMACGrasshopper"/> class.
        /// </summary>
        public CMACGrasshopper()
            : this(GenerateRandomBytes(32))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMACGrasshopper"/> class with the specified key data.
        /// </summary>
        /// <param name="key">
        /// The secret key for <see cref="CMACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>.
        /// </exception>
        public CMACGrasshopper(byte[] key)
            : this(GrasshopperAlgorithmFullName, key)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMACGrasshopper"/> class with the specified key data
        /// and using the specified implementation of <see cref="Grasshopper"/>.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the <see cref="Grasshopper"/> implementation to use. 
        /// </param>
        /// <param name="key">
        /// The secret key for <see cref="CMACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>. 
        /// </exception>
        public CMACGrasshopper(string algorithmName, byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            _cmacAlgorithm = new CMACAlgorithm(algorithmName, key, s_irreduciblePolynomial, Grasshopper.Create);
        }

        /// <summary>
        /// Initializes an instance of <see cref="CMACGrasshopper"/>.
        /// </summary>
        public override void Initialize()
            => _cmacAlgorithm.Initialize();

        /// <summary>
        /// Routes data written to the object into the <see cref="Grasshopper"/>
        /// encryptor for computing the Cipher-based Message Authentication Code (CMAC).
        /// </summary>
        /// <param name="array">
        /// The input data.
        /// </param>
        /// <param name="ibStart">
        /// The offset into the byte array from which to begin using data.
        /// </param>
        /// <param name="cbSize">
        /// The number of bytes in the array to use as data.
        /// </param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
            => _cmacAlgorithm.TransformBlock(array, ibStart, cbSize, null, 0);

        /// <summary>
        /// Returns the computed Cipher-based Message Authentication Code (CMAC)
        /// after all data is written to the object.
        /// </summary>
        /// <returns>
        /// The computed MAC.
        /// </returns>
        protected override byte[] HashFinal()
        {
            _cmacAlgorithm.TransformFinalBlock(EmptyArray<byte>.Value, 0, 0);
            return _cmacAlgorithm.Hash;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="CMACGrasshopper"/>
        /// and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// <c>true</c> to release both managed and unmanaged resources;
        /// <c>false</c> to release only unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _cmacAlgorithm.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}