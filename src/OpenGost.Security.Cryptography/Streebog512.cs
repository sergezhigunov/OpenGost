using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes the <see cref="Streebog512"/> hash for the input data.
/// </summary>
[ComVisible(true)]
public abstract class Streebog512 : HashAlgorithm
{
    /// <summary>
    /// Initializes an instance of <see cref="Streebog512"/>.
    /// </summary>
    protected Streebog512()
    {
        HashSizeValue = 512;
    }

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="Streebog512"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="Streebog512"/>.
    /// </returns>
    [ComVisible(false)]
    public static new Streebog512 Create()
        => new Streebog512Managed();
}
