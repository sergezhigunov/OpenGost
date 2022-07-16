namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    public const string GostECDsaAlgorithmName = nameof(GostECDsa);

    public const string GrasshopperAlgorithmName = nameof(Grasshopper);
    public const string CMACGrasshopperAlgorithmName = nameof(CMACGrasshopper);
    public const string MagmaAlgorithmName = nameof(Magma);
    public const string CMACMagmaAlgorithmName = nameof(CMACMagma);

    public const string Streebog256AlgorithmName = nameof(Streebog256);
    public const string HMACStreebog256AlgorithmName = nameof(HMACStreebog256);
    public const string Streebog512AlgorithmName = nameof(Streebog512);
    public const string HMACStreebog512AlgorithmName = nameof(HMACStreebog512);

    public const string GostECDsa256OidValue = "1.2.643.7.1.1.1.1";
    public const string GostECDsa512OidValue = "1.2.643.7.1.1.1.2";
    public const string Streebog256OidValue = "1.2.643.7.1.1.2.2";
    public const string Streebog512OidValue = "1.2.643.7.1.1.2.3";
}
