namespace Gost.Security.Cryptography
{
    internal static class CryptoConstants
    {
        private const string FullNamePrefix = nameof(Gost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

        internal const string GrasshopperAlgorithmName = nameof(Grasshopper);
        internal const string GrasshopperManagedAlgorithmName = nameof(GrasshopperManaged);
        internal const string GrasshopperAlgorithmFullName = FullNamePrefix + GrasshopperAlgorithmName;
        internal const string GrasshopperManagedAlgorithmFullName = FullNamePrefix + GrasshopperManagedAlgorithmName;

        internal const string MagmaAlgorithmName = nameof(Magma);
        internal const string MagmaManagedAlgorithmName = nameof(MagmaManaged);
        internal const string MagmaAlgorithmFullName = FullNamePrefix + MagmaAlgorithmName;
        internal const string MagmaManagedAlgorithmFullName = FullNamePrefix + MagmaManagedAlgorithmName;

        internal const string Streebog512AlgorithmName = nameof(Streebog512);
        internal const string Streebog512ManagedAlgorithmName = nameof(Streebog512Managed);
        internal const string Streebog512AlgorithmFullName = FullNamePrefix + Streebog512AlgorithmName;
        internal const string Streebog512ManagedAlgorithmFullName = FullNamePrefix + Streebog512ManagedAlgorithmName;

        internal const string Streebog256AlgorithmName = nameof(Streebog256);
        internal const string Streebog256ManagedAlgorithmName = nameof(Streebog256Managed);
        internal const string Streebog256AlgorithmFullName = FullNamePrefix + Streebog256AlgorithmName;
        internal const string Streebog256ManagedAlgorithmFullName = FullNamePrefix + Streebog256ManagedAlgorithmName;
    }
}
