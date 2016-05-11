namespace Gost.Security.Cryptography
{
    internal static class CryptoConstants
    {
        private const string FullNamePrefix = nameof(Gost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

        internal const string GostECDsaAlgorithmName = nameof(GostECDsa);

        internal const string GrasshopperAlgorithmFullName = FullNamePrefix + nameof(Grasshopper);

        internal const string MagmaAlgorithmFullName = FullNamePrefix + nameof(Magma);

        internal const string Streebog512AlgorithmFullName = FullNamePrefix + nameof(Streebog512);
        internal const string HMACStreebog512AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog512);

        internal const string Streebog256AlgorithmFullName = FullNamePrefix + nameof(Streebog256);
        internal const string HMACStreebog256AlgorithmFullName = FullNamePrefix + nameof(HMACStreebog256);
    }
}
