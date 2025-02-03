namespace OpenGost.Security.Cryptography;
using static CryptoConfig;
using static CryptoConstants;
using static OpenGostSignedXml;

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
        if (!_configured)
            lock (_syncRoot)
                if (!_configured)
                {
                    ConfigureCryptographicServicesCore();
                    _configured = true;
                }
    }

    private static void ConfigureCryptographicServicesCore()
    {
        AddAlgorithm(typeof(GostECDsaManaged), GostECDsaAlgorithmName);
        AddAlgorithm(typeof(GrasshopperManaged), GrasshopperAlgorithmName);
        AddAlgorithm(typeof(CMACGrasshopper), CMACGrasshopperAlgorithmName);
        AddAlgorithm(typeof(MagmaManaged), MagmaAlgorithmName);
        AddAlgorithm(typeof(CMACMagma), CMACMagmaAlgorithmName);
        AddAlgorithm(typeof(Streebog256Managed), Streebog256AlgorithmName, XmlDsigStreebog256Url);
        AddAlgorithm(typeof(HMACStreebog256), HMACStreebog256AlgorithmName, XmlDsigHMACStreebog256Url);
        AddAlgorithm(typeof(Streebog512Managed), Streebog512AlgorithmName, XmlDsigStreebog512Url);
        AddAlgorithm(typeof(HMACStreebog512), HMACStreebog512AlgorithmName, XmlDsigHMACStreebog512Url);
        AddAlgorithm(typeof(GostECDsa256SignatureDescription), XmlDsigGostECDsaStreebog256Url);
        AddAlgorithm(typeof(GostECDsa512SignatureDescription), XmlDsigGostECDsaStreebog512Url);
        AddOID(Oids.Streebog256, Streebog256AlgorithmName);
        AddOID(Oids.Streebog512, Streebog512AlgorithmName);
    }
}
