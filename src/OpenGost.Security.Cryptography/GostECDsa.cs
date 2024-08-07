﻿using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Provides an abstract base class that encapsulates the GOST 34.10-2018 algorithm.
/// </summary>
[ComVisible(true)]
public abstract class GostECDsa : ECDsa
{
    private static readonly KeySizes[] _legalKeySizes = [new(256, 512, 256)];

    /// <summary>
    /// Gets the name of the signature algorithm.
    /// </summary>
    /// <value>
    /// Always &quot;GostECDsa&quot;.
    /// </value>
    public override string SignatureAlgorithm => CryptoConstants.GostECDsaAlgorithmName;

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa"/> class.
    /// </summary>
    protected GostECDsa()
    {
        LegalKeySizesValue = _legalKeySizes;
        KeySizeValue = 512;
    }

    #region Creation factory methods

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="GostECDsa"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="GostECDsa"/>.
    /// </returns>
    [ComVisible(false)]
    public static new GostECDsa Create()
        => Create(CryptoConstants.GostECDsaAlgorithmName);

    /// <summary>
    /// Creates an instance of a specified implementation of <see cref="GostECDsa"/> algorithm.
    /// </summary>
    /// <param name="algorithmName">
    /// The name of the specific implementation of <see cref="GostECDsa"/> to be used.
    /// </param>
    /// <returns>
    /// A new instance of <see cref="GostECDsa"/> using the specified implementation.
    /// </returns>
    [ComVisible(false)]
    public static new GostECDsa Create(string algorithmName)
        => (GostECDsa)CryptoConfig.CreateFromName(algorithmName)!;

    #endregion
}
