using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static SecurityCryptographyStrings;

    /// <summary>
    /// Represents the base class from which all implementations of the <see cref="Grasshopper"/> symmetric encryption algorithm must inherit.
    /// </summary>
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
            FeedbackSizeValue = BlockSizeValue;
            LegalBlockSizesValue = s_legalBlockSizes;
            LegalKeySizesValue = s_legalKeySizes;
        }

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
                if (value == 0 || value % (BlockSizeValue / 8) != 0) throw new CryptographicException(InvalidFeedbackSize);

                FeedbackSizeValue = value;
            }
        }

        /// <summary>
        /// Gets or sets the initialization vector (<see cref="SymmetricAlgorithm.IV"/>) for the symmetric algorithm.
        /// </summary>
        /// <value>
        /// The initialization vector.
        /// </value>
        /// <exception cref="ArgumentNullException">
        /// An attempt was made to set the initialization vector to null.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The initialization vector length is zero or not evenly devisable by block size.
        /// </exception>
        public override byte[] IV
        {
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (value.Length == 0 || value.Length % (BlockSizeValue / 8) != 0) throw new CryptographicException(InvalidIVSize);

                FeedbackSize = value.Length;

                IVValue = (byte[])value.Clone();
            }
        }
    }
}
