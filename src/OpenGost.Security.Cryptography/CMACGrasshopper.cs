using System;
using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Cipher-based Message Authentication Code (CMAC) using <see cref="Grasshopper"/> algorithm.
    /// </summary>
    [ComVisible(true)]
    public class CMACGrasshopper : CMAC
    {
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
            : base()
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            SymmetricAlgorithmName = algorithmName;
            base.Key = key;
        }
    }
}