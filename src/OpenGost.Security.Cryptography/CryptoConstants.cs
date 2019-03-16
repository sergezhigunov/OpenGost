namespace OpenGost.Security.Cryptography
{
    internal static class CryptoConstants
    {
        private const string FullNamePrefix = nameof(OpenGost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

        internal const string GostECDsa512SignatureFormatterFullName = FullNamePrefix + nameof(GostECDsa512SignatureFormatter);
        internal const string GostECDsa512SignatureDeformatterFullName = FullNamePrefix + nameof(GostECDsa512SignatureDeformatter);

        internal const string GostECDsa256SignatureFormatterFullName = FullNamePrefix + nameof(GostECDsa256SignatureFormatter);
        internal const string GostECDsa256SignatureDeformatterFullName = FullNamePrefix + nameof(GostECDsa256SignatureDeformatter);

        internal const string GostECDsa512SignatureDescriptionFullName = FullNamePrefix + nameof(GostECDsa512SignatureDescription);
        internal const string GostECDsa256SignatureDescriptionFullName = FullNamePrefix + nameof(GostECDsa256SignatureDescription);

        internal const string GostECDsa512AlgorithmName = nameof(GostECDsa512);
        internal const string GostECDsa512AlgorithmFullName = FullNamePrefix + GostECDsa512AlgorithmName;

        internal const string GostECDsa256AlgorithmName = nameof(GostECDsa256);
        internal const string GostECDsa256AlgorithmFullName = FullNamePrefix + GostECDsa256AlgorithmName;

        internal const string GrasshopperAlgorithmFullName = FullNamePrefix + nameof(Grasshopper);
        internal const string CMACGrasshopperAlgorithmFullName = FullNamePrefix + nameof(CMACGrasshopper);

        internal const string MagmaAlgorithmFullName = FullNamePrefix + nameof(Magma);
        internal const string CMACMagmaAlgorithmFullName = FullNamePrefix + nameof(CMACMagma);

        internal const string Streebog512AlgorithmFullName = FullNamePrefix + nameof(Streebog512);
        internal const string HMACStreebog512AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog512);

        internal const string Streebog256AlgorithmFullName = FullNamePrefix + nameof(Streebog256);
        internal const string HMACStreebog256AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog256);

        internal const string GostECDsa256OidValue = "1.2.643.7.1.1.1.1";
        internal const string GostECDsa512OidValue = "1.2.643.7.1.1.1.2";

        internal const string Streebog256OidValue = "1.2.643.7.1.1.2.2";
        internal const string Streebog512OidValue = "1.2.643.7.1.1.2.3";
    }
}
