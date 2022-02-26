using System.Diagnostics.CodeAnalysis;

namespace OpenGost.Security.Cryptography.Tests;

[ExcludeFromCodeCoverage]
public abstract class CryptoConfigRequiredTest
{
    static CryptoConfigRequiredTest() => OpenGostCryptoConfig.ConfigureCryptographicServices();
}
