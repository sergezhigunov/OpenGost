using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    /// <summary>
    /// Provides an abstract base class that encapsulates the 256-bit version of
    /// the <see cref="GostECDsa"/> algorithm.
    /// </summary>
    [ComVisible(true)]
    public abstract class GostECDsa256 : GostECDsa
    {
        private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(256, 256, 0) };

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        /// <value>
        /// Always <c>"GostECDsa256"</c>.
        /// </value>
        public override string SignatureAlgorithm => GostECDsa256AlgorithmName;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa256"/> class.
        /// </summary>
        protected GostECDsa256()
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySizeValue = 256;
        }

        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="GostECDsa256"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="GostECDsa256"/>.
        /// </returns>
        [ComVisible(false)]
        public new static GostECDsa256 Create()
            => Create(GostECDsa256AlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="GostECDsa256"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="GostECDsa256"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="GostECDsa256"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public new static GostECDsa256 Create(string algorithmName)
            => (GostECDsa256)CreateFromName(algorithmName);

        #endregion
    }
}