using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
#if NET45
    using static CryptoConfig;
    using static CryptoConstants; 
#endif
    using static SecurityCryptographyStrings;

    /// <summary>
    /// Represents the base class from which all implementations of the <see cref="Grasshopper"/> symmetric encryption algorithm must inherit.
    /// </summary>
    [ComVisible(true)]
    public abstract class Grasshopper : SymmetricAlgorithm
    {
        private static readonly KeySizes[]
            s_legalBlockSizes = { new KeySizes(128, 128, 0) },
            s_legalKeySizes = { new KeySizes(256, 256, 0) };

        /// <summary>
        /// Initializes a new instance of <see cref="Grasshopper"/>.
        /// </summary>
        protected Grasshopper()
        {
            KeySizeValue = 256;
            BlockSizeValue = 128;
#if NET45
            FeedbackSizeValue = BlockSizeValue; 
#endif
            LegalBlockSizesValue = s_legalBlockSizes;
            LegalKeySizesValue = s_legalKeySizes;
        }

#if NET45
        /// <summary>
        /// Gets or sets the feedback size, in bits, of the cryptographic operation.
        /// </summary>
        /// <value>
        /// The feedback size in bits.
        /// </value>
        /// <exception cref="CryptographicException">
        /// The feedback size is zero or not evenly devisable by block size.
        /// </exception>
        public override int FeedbackSize
        {
            set
            {
                if (value == 0 || value % (BlockSizeValue / 8) != 0) throw new CryptographicException(CryptographicInvalidFeedbackSize);

                FeedbackSizeValue = value;
            }
        } 
#endif

        /// <summary>
        /// Gets or sets the initialization vector (<see cref="SymmetricAlgorithm.IV"/>) for the symmetric algorithm.
        /// </summary>
        /// <value>
        /// The initialization vector.
        /// </value>
        /// <exception cref="ArgumentNullException">
        /// An attempt was made to set the initialization vector to <c>null</c>.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The initialization vector length is zero or not evenly devisable by block size.
        /// </exception>
        public override byte[] IV
        {
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (value.Length == 0 || value.Length % (BlockSizeValue / 8) != 0) throw new CryptographicException(CryptographicInvalidIVSize);

#if NET45
                FeedbackSize = value.Length; 
#endif

                IVValue = (byte[])value.Clone();
            }
        }

#if NET45
        #region Creation factory methods 

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="Grasshopper"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="Grasshopper"/>.
        /// </returns>
        [ComVisible(false)]
        public new static Grasshopper Create()
            => Create(GrasshopperAlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="Grasshopper"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="Grasshopper"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="Grasshopper"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public new static Grasshopper Create(string algorithmName)
            => (Grasshopper)CreateFromName(algorithmName);

        #endregion  
#endif
    }
}