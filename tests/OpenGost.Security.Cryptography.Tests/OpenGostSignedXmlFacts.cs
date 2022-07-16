using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class OpenGostSignedXmlFacts
{
    [Theory]
    [InlineData(
        "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256",
        OpenGostSignedXml.XmlDsigGostECDsaStreebog256Url)]
    [InlineData(
        "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512",
        OpenGostSignedXml.XmlDsigGostECDsaStreebog512Url)]
    [InlineData(
        "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256",
        OpenGostSignedXml.XmlDsigStreebog256Url)]
    [InlineData(
        "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512",
        OpenGostSignedXml.XmlDsigStreebog512Url)]
    public void ConstantsHaveCorrectValues(string expected, string actual)
        => Assert.Equal(expected, actual);
}
