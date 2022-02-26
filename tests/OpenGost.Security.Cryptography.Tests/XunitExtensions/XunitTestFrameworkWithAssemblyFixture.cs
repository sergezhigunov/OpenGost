using System.Diagnostics.CodeAnalysis;
using OpenGost.Security.Cryptography;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace OpenGost.XunitExtensions;

[ExcludeFromCodeCoverage]
public class XunitTestFrameworkWithAssemblyFixture : XunitTestFramework
{
    public XunitTestFrameworkWithAssemblyFixture(IMessageSink messageSink)
        : base(messageSink)
    {
        OpenGostCryptoConfig.ConfigureCryptographicServices();
    }
}
