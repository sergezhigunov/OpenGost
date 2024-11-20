using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes the <see cref="Streebog256"/> hash for the input data.
/// </summary>
[ComVisible(true)]
public abstract class Streebog256 : HashAlgorithm
{
    /// <summary>
    /// Initializes an instance of <see cref="Streebog256"/>.
    /// </summary>
    protected Streebog256()
    {
        HashSizeValue = 256;
    }

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="Streebog256"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="Streebog256"/>.
    /// </returns>
    [ComVisible(false)]
    public static new Streebog256 Create()
        => new Streebog256Managed();
}
