using Xunit;
namespace OpenGost.Security.Cryptography.Tests;
using static OpenGostSignedXml;

public class OpenGostSignedXmlFacts
{
    [Theory]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256",
        XmlDsigGostECDsaStreebog256Url)]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512",
        XmlDsigGostECDsaStreebog512Url)]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256", XmlDsigStreebog256Url)]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512", XmlDsigStreebog512Url)]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr34112012-256", XmlDsigHMACStreebog256Url)]
    [InlineData("urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr34112012-512", XmlDsigHMACStreebog512Url)]
    public void ConstantsHaveCorrectValues(string expected, string actual)
        => Assert.Equal(expected, actual);
}
