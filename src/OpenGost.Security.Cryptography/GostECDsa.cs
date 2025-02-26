using System.Runtime.InteropServices;

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

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="GostECDsa"/> algorithm.
    /// </summary>
    /// <returns>
    /// A new instance of <see cref="GostECDsa"/>.
    /// </returns>
    [ComVisible(false)]
    public static new GostECDsa Create()
        => new GostECDsaManaged();

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="GostECDsa"/> algorithm with a newly generated
    /// key over the specified curve.
    /// </summary>
    /// <param name="curve">
    /// The curve to use for key generation.
    /// </param>
    /// <returns>
    /// A new instance of <see cref="GostECDsa"/>.
    /// </returns>
    [ComVisible(false)]
    public static new GostECDsa Create(ECCurve curve)
    {
        var algorithm = new GostECDsaManaged();
        algorithm.GenerateKey(curve);
        return algorithm;
    }

    /// <summary>
    /// Creates an instance of the default implementation of <see cref="GostECDsa"/> algorithm using the specified
    /// parameters as the key.
    /// </summary>
    /// <param name="parameters">
    /// The parameters representing the key to use.
    /// </param>
    /// <returns>
    /// A new instance of <see cref="GostECDsa"/>.
    /// </returns>
    [ComVisible(false)]
    public static new GostECDsa Create(ECParameters parameters)
    {
        var algorithm = new GostECDsaManaged();
        algorithm.ImportParameters(parameters);
        return algorithm;
    }
}
