using System.Security;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

using static CryptoConfig;
using static CryptoConstants;

/// <summary>
/// Contains an entry point to configure cryptographic services.
/// </summary>
public static class OpenGostCryptoConfig
{
    private static readonly object _syncRoot = new();
    private static bool _configured;

    /// <summary>
    /// Configures OpenGost cryptographic services.
    /// </summary>
    public static void ConfigureCryptographicServices()
    {
        if(!_configured)
            lock (_syncRoot)
                if (!_configured)
                {
                    ConfigureCryptographicServicesCore();
                    _configured = true;
                }
    }

    [SecuritySafeCritical]
    private static void ConfigureCryptographicServicesCore()
    {
        AddAlgorithm(typeof(GostECDsaManaged), GostECDsaAlgorithmName, GostECDsaAlgorithmFullName);
        AddAlgorithm(typeof(GrasshopperManaged), GrasshopperAlgorithmName, GrasshopperAlgorithmFullName);
        AddAlgorithm(typeof(CMACGrasshopper), CMACGrasshopperAlgorithmName, CMACGrasshopperAlgorithmFullName);
        AddAlgorithm(typeof(MagmaManaged), MagmaAlgorithmName, MagmaAlgorithmFullName);
        AddAlgorithm(typeof(CMACMagma), CMACMagmaAlgorithmName, CMACMagmaAlgorithmFullName);
        AddAlgorithm(typeof(Streebog256Managed), Streebog256AlgorithmName, Streebog256AlgorithmFullName);
        AddAlgorithm(typeof(HMACStreebog256), HMACStreebog256AlgorithmName, HMACStreebog256AlgorithmFullName);
        AddAlgorithm(typeof(Streebog512Managed), Streebog512AlgorithmName, Streebog512AlgorithmFullName);
        AddAlgorithm(typeof(HMACStreebog512), HMACStreebog512AlgorithmName, HMACStreebog512AlgorithmFullName);
        AddOID(Streebog256OidValue, Streebog256AlgorithmName, Streebog256AlgorithmFullName);
        AddOID(Streebog512OidValue, Streebog512AlgorithmName, Streebog512AlgorithmFullName);
    }
}
