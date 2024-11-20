using System.Diagnostics.CodeAnalysis;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace OpenGost.Security.Cryptography.Tests.XunitExtensions;

[ExcludeFromCodeCoverage]
public class XunitTestFrameworkWithAssemblyFixture : XunitTestFramework
{
    public XunitTestFrameworkWithAssemblyFixture(IMessageSink messageSink)
        : base(messageSink)
    {
        OpenGostCryptoConfig.ConfigureCryptographicServices();
    }
}
