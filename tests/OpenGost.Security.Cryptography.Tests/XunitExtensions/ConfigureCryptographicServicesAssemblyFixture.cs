using System.Diagnostics.CodeAnalysis;

namespace OpenGost.Security.Cryptography.Tests.XunitExtensions;

[ExcludeFromCodeCoverage]
public class ConfigureCryptographicServicesAssemblyFixture
{
    public ConfigureCryptographicServicesAssemblyFixture()
    {
        OpenGostCryptoConfig.ConfigureCryptographicServices();
    }
}
