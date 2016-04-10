using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Message Authentication Code (MAC) using <see cref="Grasshopper"/> algorithm.
    /// </summary>
    public class MACGrasshopper : KeyedHashAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class.
        /// </summary>
        public MACGrasshopper()
            : this(GenerateRandomBytes(32))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class with the specified key data.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACGrasshopper(byte[] rgbKey)
            : this(GrasshopperManagedAlgorithmFullName, rgbKey)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class with the specified key data
        /// and using the specified implementation of <see cref="Grasshopper"/>.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the <see cref="Grasshopper"/> implementation to use. 
        /// </param>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACGrasshopper(string algorithmName, byte[] rgbKey)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes an instance of <see cref="MACGrasshopper"/>.
        /// </summary>
        public override void Initialize()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Routes data written to the object into the <see cref="Grasshopper"/>
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
