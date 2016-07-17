using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;

    /// <summary>
    /// Provides an abstract base class that encapsulates the 256-bit version of
    /// the <see cref="GostECDsa"/> algorithm.
    /// </summary>
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
    }
}