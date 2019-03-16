using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class GostECDsa512SignatureDescriptionTests : SignatureDescriptionTest<GostECDsa512SignatureDescription>
    {
        [Fact]
        public void ValidateCreateDigest()
        {
            using (HashAlgorithm digest = CreateDigest())
            {
                Assert.NotNull(digest);
                Assert.True(digest is Streebog512);
            }
        }

        [Fact]
        public void ValidateCreateDeformatter()
        {
            AsymmetricSignatureDeformatter deformatter = CreateDeformatter(GostECDsa512.Create());

            Assert.NotNull(deformatter);
            Assert.True(deformatter is GostECDsa512SignatureDeformatter);
        }

        [Fact]
        public void ValidateCreateFormatter()
        {
            AsymmetricSignatureFormatter formatter = CreateFormatter(GostECDsa512.Create());

            Assert.NotNull(formatter);
            Assert.True(formatter is GostECDsa512SignatureFormatter);
        }
    }
}
