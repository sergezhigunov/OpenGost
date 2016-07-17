using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;

    /// <summary>
    /// Provides an abstract base class that encapsulates the 512-bit version of
    /// the <see cref="GostECDsa"/> algorithm.
    /// </summary>
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
    }
}