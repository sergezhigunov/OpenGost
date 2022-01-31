namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    private const string Namespace = $"{nameof(OpenGost)}.{nameof(Security)}.{nameof(Cryptography)}";

    public const string GostECDsaAlgorithmName = nameof(GostECDsa);
    public const string GostECDsaAlgorithmFullName = $"{Namespace}.{GostECDsaAlgorithmName}";

    public const string GrasshopperAlgorithmFullName = $"{Namespace}.{nameof(Grasshopper)}";
    public const string CMACGrasshopperAlgorithmFullName = $"{Namespace}.{nameof(CMACGrasshopper)}";
    public const string MagmaAlgorithmFullName = $"{Namespace}.{nameof(Magma)}";

    public const string Streebog512AlgorithmFullName = $"{Namespace}.{nameof(Streebog512)}";
    public const string Streebog256AlgorithmFullName = $"{Namespace}.{nameof(Streebog256)}";

    public const string GostECDsa256OidValue = "1.2.643.7.1.1.1.1";
    public const string GostECDsa512OidValue = "1.2.643.7.1.1.1.2";
}
