using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Provides an abstract base class that encapsulates the 256-bit version of
/// the GOST R 34.10-2012 <see cref="ECDsa"/> algorithm.
/// </summary>
[ComVisible(true)]
public abstract class GostECDsa256 : ECDsa
{
    private static readonly KeySizes[] _legalKeySizes = { new KeySizes(256, 256, 0) };

    /// <summary>
    /// Gets the name of the signature algorithm.
    /// </summary>
    /// <value>
    /// Always &quot;GostECDsa256&quot;.
    /// </value>
    public override string SignatureAlgorithm => CryptoConstants.GostECDsa256AlgorithmName;

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa256"/> class.
    /// </summary>
    protected GostECDsa256()
    {
        LegalKeySizesValue = _legalKeySizes;
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
    public static new GostECDsa256 Create()
        => Create(CryptoConstants.GostECDsa256AlgorithmFullName);

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
    public static new GostECDsa256 Create(string algorithmName)
        => (GostECDsa256)CryptoConfig.CreateFromName(algorithmName);

    #endregion
}
