using System;
using System.Runtime.InteropServices;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Cipher-based Message Authentication Code (CMAC) using <see cref="Magma"/> algorithm.
    /// </summary>
    [ComVisible(true)]
    public class CMACMagma : CMAC
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CMACMagma"/> class.
        /// </summary>
        public CMACMagma()
            : this(GenerateRandomBytes(32))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMACMagma"/> class with the specified key data.
        /// </summary>
        /// <param name="key">
        /// The secret key for <see cref="CMACMagma"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>. 
        /// </exception>
        public CMACMagma(byte[] key)
            : this(MagmaAlgorithmFullName, key)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMACMagma"/> class with the specified key data
        /// and using the specified implementation of <see cref="Magma"/>.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the <see cref="Magma"/> implementation to use. 
        /// </param>
        /// <param name="key">
        /// The secret key for <see cref="CMACMagma"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>. 
        /// </exception>
        public CMACMagma(string algorithmName, byte[] key)
            : base()
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            SymmetricAlgorithmName = algorithmName;
            base.Key = key;
        }
    }
}