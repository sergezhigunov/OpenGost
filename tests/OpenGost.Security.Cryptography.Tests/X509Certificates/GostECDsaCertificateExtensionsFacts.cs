using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    public class GostECDsaCertificateExtensionsFacts : CryptoConfigRequiredTest
    {
        [Theory]
        [InlineData("GostECDsa256")]
        [InlineData("GostECDsa512")]
        public void GetECDsaPublicKey_ReturnsPublicKey(string certificateName)
        {
            var certificate = new X509Certificate2(
                ResourceUtils.GetBinaryResource(
                    $"OpenGost.Security.Cryptography.Tests.Resources.{certificateName}.cer"));

            using var publicKey = certificate.GetECDsaPublicKey();

            Assert.NotNull(publicKey);
        }
    }
}
