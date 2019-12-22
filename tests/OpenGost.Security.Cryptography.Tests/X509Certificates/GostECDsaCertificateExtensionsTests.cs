using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    public class GostECDsaCertificateExtensionsTests : CryptoConfigRequiredTest
    {
        [Theory]
        [InlineData("GostECDsa256")]
        [InlineData("GostECDsa512")]
        public void GetPublicKeyFromX509Certificate2(string certificateName)
        {
            var certificate = new X509Certificate2(
                ResourceUtils.GetBinaryResource(
                    $"OpenGost.Security.Cryptography.Tests.Resources.{certificateName}.cer"));

            using (var publicKey = certificate.GetECDsaPublicKey())
            {
                Assert.NotNull(publicKey);
            }
        }
    }
}
