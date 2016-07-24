using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    /// <summary>
    /// Provides an abstract base class that encapsulates the 512-bit version of
    /// the <see cref="GostECDsa"/> algorithm.
    /// </summary>
    [ComVisible(true)]
    public abstract class GostECDsa512 : GostECDsa
    {
        private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(512, 512, 0) };

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        /// <value>
        /// Always <c>"GostECDsa512"</c>.
        /// </value>
        public override string SignatureAlgorithm => GostECDsa512AlgorithmName;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa512"/> class.
        /// </summary>
        protected GostECDsa512()
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySizeValue = 512;
        }

        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="GostECDsa512"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="GostECDsa512"/>.
        /// </returns>
        [ComVisible(false)]
        public new static GostECDsa512 Create()
            => Create(GostECDsa512AlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="GostECDsa512"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="GostECDsa512"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="GostECDsa512"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public new static GostECDsa512 Create(string algorithmName)
            => (GostECDsa512)CreateFromName(algorithmName);

        #endregion
    }
}