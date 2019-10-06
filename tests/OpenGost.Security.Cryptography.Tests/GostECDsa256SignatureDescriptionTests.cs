using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class GostECDsa256SignatureDescriptionTests : SignatureDescriptionTest<GostECDsa256SignatureDescription>
    {
        [Fact]
        public void ValidateCreateDigest()
        {
            using (var digest = CreateDigest())
            {
                Assert.NotNull(digest);
                Assert.True(digest is Streebog256);
            }
        }

        [Fact]
        public void ValidateCreateDeformatter()
        {
            var deformatter = CreateDeformatter(GostECDsa256.Create());

            Assert.NotNull(deformatter);
            Assert.True(deformatter is GostECDsa256SignatureDeformatter);
        }

        [Fact]
        public void ValidateCreateFormatter()
        {
            var formatter = CreateFormatter(GostECDsa256.Create());

            Assert.NotNull(formatter);
            Assert.True(formatter is GostECDsa256SignatureFormatter);
        }
    }
}
