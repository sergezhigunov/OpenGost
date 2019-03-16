using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace OpenGost.Security.Cryptography.X509Certificates
{

    public class GostECDsaCertificateExtensionsTests : CryptoConfigRequiredTest
    {
        [Theory(DisplayName = nameof(GetPublicKeyFromX509Certificate2))]
        [MemberData(nameof(TestCertificates))]
        public void GetPublicKeyFromX509Certificate2(X509Certificate2 certificate)
        {
            using (GostECDsa publicKey = certificate.GetECDsaPublicKey())
            {
                Assert.NotNull(publicKey);
            }
        }

        public static IEnumerable<object[]> TestCertificates()
        {
            yield return new[] { new X509Certificate2(ResourceUtils.GetBinaryResource("OpenGost.Security.Cryptography.Tests.Resources.GostECDsa256.cer")) };
            yield return new[] { new X509Certificate2(ResourceUtils.GetBinaryResource("OpenGost.Security.Cryptography.Tests.Resources.GostECDsa512.cer")) };
        }
    }
}
