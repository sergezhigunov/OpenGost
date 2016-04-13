using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    /// <summary>
    /// Computes the <see cref="Streebog256"/> hash for the input data. 
    /// </summary>
    public abstract class Streebog256 : HashAlgorithm
    {
        /// <summary>
        /// Initializes an instance of <see cref="Streebog256"/>.
        /// </summary>
        protected Streebog256()
        {
            HashSizeValue = 256;
        }

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="Streebog256"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="Streebog256"/>.
        /// </returns>
        public new static Streebog256 Create()
            => Create(Streebog256AlgorithmName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="Streebog256"/> algorithm.
        /// </summary>
        /// <param name="algName">
        /// The name of the specific implementation of <see cref="Streebog256"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="Streebog256"/> using the specified implementation.
        /// </returns>
        public new static Streebog256 Create(string algName)
            => (Streebog256)CreateFromName(algName);
    }
}
