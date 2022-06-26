using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Contains information about the properties of a 512-bit <see cref="GostECDsa"/> digital signature.
/// </summary>
public class GostECDsa512SignatureDescription : SignatureDescription
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa512SignatureDescription"/> class.
    /// </summary>
    public GostECDsa512SignatureDescription()
    {
        KeyAlgorithm = typeof(GostECDsa).AssemblyQualifiedName;
        DigestAlgorithm = CryptoConstants.Streebog512AlgorithmName;
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
        return Streebog512.Create();
    }

    /// <inheritdoc/>
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        var formatter = new GostECDsaSignatureFormatter();
        formatter.SetKey(key);
        return formatter;
    }
}
