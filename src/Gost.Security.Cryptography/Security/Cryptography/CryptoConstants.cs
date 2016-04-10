namespace Gost.Security.Cryptography
{
    internal static class CryptoConstants
    {
        private const string FullNamePrefix = nameof(Gost) + "." + nameof(Security) + "." + nameof(Cryptography) + ".";

        internal const string GrasshopperManagedAlgorithmName = nameof(GrasshopperManaged);
        internal const string MagmaManagedAlgorithmName = nameof(MagmaManaged);
        internal const string Streebog512ManagedAlgorithmName = nameof(Streebog512Managed);
        internal const string Streebog256ManagedAlgorithmName = nameof(Streebog256Managed);
        internal const string GrasshopperManagedAlgorithmFullName = FullNamePrefix + GrasshopperManagedAlgorithmName;
        internal const string MagmaManagedAlgorithmFullName = FullNamePrefix + MagmaManagedAlgorithmName;
        internal const string Streebog512ManagedAlgorithmFullName = FullNamePrefix + Streebog512ManagedAlgorithmName;
        internal const string Streebog256ManagedAlgorithmFullName = FullNamePrefix + Streebog256ManagedAlgorithmName;
    }
}
