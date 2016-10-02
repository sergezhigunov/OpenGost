using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
#if NET45
    using static CryptoConfig;
    using static CryptoConstants; 
#endif

    /// <summary>
    /// Computes the <see cref="Streebog256"/> hash for the input data. 
    /// </summary>
    [ComVisible(true)]
    public abstract class Streebog256 : HashAlgorithm
    {
#if NETCOREAPP1_0
        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <value>
        /// The size, in bits, of the computed hash code.
        /// </value>
        public override int HashSize => 256;
#endif

        /// <summary>
        /// Initializes an instance of <see cref="Streebog256"/>.
        /// </summary>
        protected Streebog256()
        {
#if NET45
            HashSizeValue = 256; 
#endif
        }

#if NET45
        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="Streebog256"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="Streebog256"/>.
        /// </returns>
        [ComVisible(false)]
        public new static Streebog256 Create()
            => Create(Streebog256AlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="Streebog256"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="Streebog256"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="Streebog256"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public new static Streebog256 Create(string algorithmName)
            => (Streebog256)CreateFromName(algorithmName);

        #endregion  
#endif
    }
}
