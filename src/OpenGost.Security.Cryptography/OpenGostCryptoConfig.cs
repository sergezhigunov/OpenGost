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
        AddAlgorithm(typeof(GostECDsaManaged), GostECDsaAlgorithmName);
        AddAlgorithm(typeof(GrasshopperManaged), GrasshopperAlgorithmName);
        AddAlgorithm(typeof(CMACGrasshopper), CMACGrasshopperAlgorithmName);
        AddAlgorithm(typeof(MagmaManaged), MagmaAlgorithmName);
        AddAlgorithm(typeof(CMACMagma), CMACMagmaAlgorithmName);
        AddAlgorithm(typeof(Streebog256Managed), Streebog256AlgorithmName, OpenGostSignedXml.XmlDsigStreebog256Url);
        AddAlgorithm(typeof(HMACStreebog256), HMACStreebog256AlgorithmName);
        AddAlgorithm(typeof(Streebog512Managed), Streebog512AlgorithmName, OpenGostSignedXml.XmlDsigStreebog512Url);
        AddAlgorithm(typeof(HMACStreebog512), HMACStreebog512AlgorithmName);
        AddAlgorithm(typeof(GostECDsa256SignatureDescription), OpenGostSignedXml.XmlDsigGostECDsaStreebog256Url);
        AddAlgorithm(typeof(GostECDsa512SignatureDescription), OpenGostSignedXml.XmlDsigGostECDsaStreebog512Url);
        AddOID(Streebog256OidValue, Streebog256AlgorithmName);
        AddOID(Streebog512OidValue, Streebog512AlgorithmName);
    }
}
