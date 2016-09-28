using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using OpenGost.Properties;
using Xunit;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    using static Resources;

    public class GostECDsaCertificateExtensionsTests : CryptoConfigRequiredTest
    {
        [Theory(DisplayName = nameof(GostECDsaCertificateExtensionsTests) + "_" + nameof(GetPublicKeyFromX509Certificate2))]
        [MemberData(nameof(TestCertificates))]
        public void GetPublicKeyFromX509Certificate2(X509Certificate2 certificate)
        {
            GostECDsa publicKey = certificate.GetECDsaPublicKey();
            Assert.NotNull(publicKey);
            using (publicKey)
            {
            }
        }

        public static IEnumerable<object[]> TestCertificates()
        {
            yield return new[] { new X509Certificate2(GostECDsa512Certificate) };
            yield return new[] { new X509Certificate2(GostECDsa256Certificate) };
        }
    }
}
