using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static System.Security.Cryptography.CryptoConfig;
using static OpenGost.Security.Cryptography.CryptoConstants;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Computes the <see cref="Streebog256"/> hash for the input data. 
    /// </summary>
    [ComVisible(true)]
    public abstract class Streebog256 : HashAlgorithm
    {
        /// <summary>
        /// Initializes an instance of <see cref="Streebog256"/>.
        /// </summary>
        protected Streebog256()
        {
            HashSizeValue = 256;
        }

        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="Streebog256"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="Streebog256"/>.
        /// </returns>
        [ComVisible(false)]
        public static new Streebog256 Create()
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
        public static new Streebog256 Create(string algorithmName)
            => (Streebog256)CreateFromName(algorithmName);

        #endregion
    }
}
