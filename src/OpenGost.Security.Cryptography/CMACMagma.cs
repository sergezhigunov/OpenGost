using System;
using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes a Cipher-based Message Authentication Code (CMAC) using <see cref="Magma"/> algorithm.
/// </summary>
[ComVisible(true)]
public class CMACMagma : CMAC
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CMACMagma"/> class.
    /// </summary>
    public CMACMagma()
        : this(CryptoUtils.GenerateRandomBytes(32))
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="CMACMagma"/> class with the specified key data.
    /// </summary>
    /// <param name="key">
    /// The secret key for <see cref="CMACMagma"/> encryption.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="key"/> parameter is <see langword="null"/>.
    /// </exception>
    public CMACMagma(byte[] key)
        : this(CryptoConstants.MagmaAlgorithmName, key)
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="CMACMagma"/> class with the specified key data
    /// and using the specified implementation of <see cref="Magma"/>.
    /// </summary>
    /// <param name="algorithmName">
    /// The name of the <see cref="Magma"/> implementation to use.
    /// </param>
    /// <param name="key">
    /// The secret key for <see cref="CMACMagma"/> encryption.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="key"/> parameter is <see langword="null"/>.
    /// </exception>
    public CMACMagma(string algorithmName, byte[] key)
        : base()
    {
        SymmetricAlgorithmName = algorithmName;
        base.Key = key ?? throw new ArgumentNullException(nameof(key));
    }
}
