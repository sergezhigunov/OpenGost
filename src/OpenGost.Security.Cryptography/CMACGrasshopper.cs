using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes a Cipher-based Message Authentication Code (CMAC) using <see cref="Grasshopper"/> algorithm.
/// </summary>
[ComVisible(true)]
public class CMACGrasshopper : CMAC
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CMACGrasshopper"/> class.
    /// </summary>
    public CMACGrasshopper()
        : this(CryptoUtils.GenerateRandomBytes(32))
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="CMACGrasshopper"/> class with the specified key data.
    /// </summary>
    /// <param name="key">
    /// The secret key for <see cref="CMACGrasshopper"/> encryption.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="key"/> parameter is <see langword="null"/>.
    /// </exception>
    public CMACGrasshopper(byte[] key)
        : base()
    {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(key);
#else
        if (key is null) throw new ArgumentNullException(nameof(key));
#endif
        SymmetricAlgorithmName = CryptoConstants.GrasshopperAlgorithmName;
        base.Key = key;
    }
}
