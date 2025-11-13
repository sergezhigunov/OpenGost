using System.Runtime.InteropServices;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Represents the base class from which all implementations of the <see cref="Grasshopper"/>
/// symmetric encryption algorithm must inherit.
/// </summary>
[ComVisible(true)]
public abstract class Grasshopper : SymmetricAlgorithm
{
    private static readonly KeySizes[]
        _legalBlockSizes = [new(128, 128, 0)],
        _legalKeySizes = [new(256, 256, 0)];

    /// <summary>
    /// Initializes a new instance of <see cref="Grasshopper"/>.
    /// </summary>
    protected Grasshopper()
    {
        KeySizeValue = 256;
        BlockSizeValue = 128;
        FeedbackSizeValue = BlockSizeValue;
        LegalBlockSizesValue = _legalBlockSizes;
        LegalKeySizesValue = _legalKeySizes;
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
            if (value == 0 || value % (BlockSizeValue / 8) != 0)
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidFeedbackSize);

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
    /// An attempt was made to set the initialization vector to <see langword="null"/>.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The initialization vector length is zero or not evenly devisable by block size.
    /// </exception>
    public override byte[] IV
    {
        set
        {

#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(value);
#else
            if (value is null) throw new ArgumentNullException(nameof(value));
#endif
            if (value.Length == 0 || value.Length % (BlockSizeValue / 8) != 0)
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidIVSize);

            FeedbackSize = value.Length;
            IVValue = (byte[])value.Clone();
        }
    }

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="Grasshopper"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="Grasshopper"/>.
    /// </returns>
    [ComVisible(false)]
    public static new Grasshopper Create()
        => new GrasshopperManaged();
}
