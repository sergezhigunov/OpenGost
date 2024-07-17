using System.Runtime.InteropServices;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Represents the base class from which all implementations of the
/// <see cref="Magma"/> symmetric encryption algorithm must inherit.
/// </summary>
[ComVisible(true)]
public abstract class Magma : SymmetricAlgorithm
{
    private static readonly KeySizes[]
        _legalBlockSizes = [new(64, 64, 0)],
        _legalKeySizes = [new(256, 256, 0)];

    /// <summary>
    /// Initializes a new instance of <see cref="Magma"/>.
    /// </summary>
    protected Magma()
    {
        KeySizeValue = 256;
        BlockSizeValue = 64;
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
            if (value is null)
                throw new ArgumentNullException(nameof(value));
#endif
            if (value.Length == 0 || value.Length % (BlockSizeValue / 8) != 0)
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidIVSize);

            FeedbackSize = value.Length;
            IVValue = (byte[])value.Clone();
        }
    }

    #region Creation factory methods

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="Magma"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="Magma"/>.
    /// </returns>
    [ComVisible(false)]
    public static new Magma Create()
        => Create(CryptoConstants.MagmaAlgorithmName);

    /// <summary>
    /// Creates an instance of a specified implementation of <see cref="Magma"/> algorithm.
    /// </summary>
    /// <param name="algorithmName">
    /// The name of the specific implementation of <see cref="Magma"/> to be used.
    /// </param>
    /// <returns>
    /// A new instance of <see cref="Magma"/> using the specified implementation.
    /// </returns>
    [ComVisible(false)]
    public static new Magma Create(string algorithmName)
        => (Magma)CryptoConfig.CreateFromName(algorithmName)!;

    #endregion
}
