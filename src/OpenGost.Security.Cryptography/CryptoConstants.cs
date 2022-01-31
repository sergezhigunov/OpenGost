namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    private const string FullNamePrefix =
        nameof(OpenGost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

    public const string GostECDsa512SignatureFormatterFullName =
        FullNamePrefix + nameof(GostECDsa512SignatureFormatter);
    public const string GostECDsa512SignatureDeformatterFullName =
        FullNamePrefix + nameof(GostECDsa512SignatureDeformatter);

    public const string GostECDsa256SignatureFormatterFullName =
        FullNamePrefix + nameof(GostECDsa256SignatureFormatter);
    public const string GostECDsa256SignatureDeformatterFullName =
        FullNamePrefix + nameof(GostECDsa256SignatureDeformatter);

    public const string GostECDsa512SignatureDescriptionFullName =
        FullNamePrefix + nameof(GostECDsa512SignatureDescription);
    public const string GostECDsa256SignatureDescriptionFullName =
        FullNamePrefix + nameof(GostECDsa256SignatureDescription);

    public const string GostECDsa512AlgorithmName = nameof(GostECDsa512);
    public const string GostECDsa512AlgorithmFullName = FullNamePrefix + GostECDsa512AlgorithmName;

    public const string GostECDsa256AlgorithmName = nameof(GostECDsa256);
    public const string GostECDsa256AlgorithmFullName = FullNamePrefix + GostECDsa256AlgorithmName;

    public const string GrasshopperAlgorithmFullName = FullNamePrefix + nameof(Grasshopper);
    public const string CMACGrasshopperAlgorithmFullName = FullNamePrefix + nameof(CMACGrasshopper);

    public const string MagmaAlgorithmFullName = FullNamePrefix + nameof(Magma);
    public const string CMACMagmaAlgorithmFullName = FullNamePrefix + nameof(CMACMagma);

    public const string Streebog512AlgorithmFullName = FullNamePrefix + nameof(Streebog512);
    public const string HMACStreebog512AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog512);

    public const string Streebog256AlgorithmFullName = FullNamePrefix + nameof(Streebog256);
    public const string HMACStreebog256AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog256);

    public const string GostECDsa256OidValue = "1.2.643.7.1.1.1.1";
    public const string GostECDsa512OidValue = "1.2.643.7.1.1.1.2";

    public const string Streebog256OidValue = "1.2.643.7.1.1.2.2";
    public const string Streebog512OidValue = "1.2.643.7.1.1.2.3";
}
