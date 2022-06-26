namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    private const string MethodPrefix = "urn:ietf:params:xml:ns:cpxmlsec:algorithms";

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

    private const string GostECDsaMethod = "gostr34102012";
    private const string StreebogMethod = "gostr34112012";

    public const string GostECDsa256SignatureMethod = $"{MethodPrefix}:{GostECDsaMethod}-{StreebogMethod}-256";
    public const string GostECDsa512SignatureMethod = $"{MethodPrefix}:{GostECDsaMethod}-{StreebogMethod}-512";
    public const string Streebog256DigestMethod = $"{MethodPrefix}:{StreebogMethod}-256";
    public const string Streebog512DigestMethod = $"{MethodPrefix}:{StreebogMethod}-512";
}
