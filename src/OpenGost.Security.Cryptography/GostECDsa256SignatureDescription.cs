using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Contains information about the properties of a 256-bit <see cref="GostECDsa"/> digital signature.
/// </summary>
public class GostECDsa256SignatureDescription : SignatureDescription
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa256SignatureDescription"/> class.
    /// </summary>
    public GostECDsa256SignatureDescription()
    {
        KeyAlgorithm = typeof(GostECDsa).AssemblyQualifiedName;
        DigestAlgorithm = CryptoConstants.Streebog256AlgorithmFullName;
    }

    /// <inheritdoc/>
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        var deformatter = new GostECDsaSignatureDeformatter();
        deformatter.SetKey(key);
        return deformatter;
    }

    /// <inheritdoc/>
    public override HashAlgorithm CreateDigest()
    {
        return Streebog256.Create();
    }

    /// <inheritdoc/>
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        var formatter = new GostECDsaSignatureFormatter();
        formatter.SetKey(key);
        return formatter;
    }
}
