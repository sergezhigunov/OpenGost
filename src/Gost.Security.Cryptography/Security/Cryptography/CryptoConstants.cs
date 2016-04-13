namespace Gost.Security.Cryptography
{
    internal static class CryptoConstants
    {
        private const string FullNamePrefix = nameof(Gost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

        internal const string GrasshopperAlgorithmName = nameof(Grasshopper);
        internal const string MagmaAlgorithmName = nameof(Magma);
        internal const string Streebog512AlgorithmName = nameof(Streebog512);
        internal const string Streebog256AlgorithmName = nameof(Streebog256);
        internal const string HMACStreebog512AlgorithmName = nameof(HMACStreebog512);
        internal const string HMACStreebog256AlgorithmName = nameof(HMACStreebog256);
    }
}
