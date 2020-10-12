using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class GostECDsa512SignatureDescriptionFacts : SignatureDescriptionTest<GostECDsa512SignatureDescription>
    {
        [Fact]
        public void CreateDigest_CreatesValidHashAlgorithm()
        {
            using var digest = CreateDigest();

            Assert.NotNull(digest);
            Assert.True(digest is Streebog512);
        }

        [Fact]
        public void CreateDeformatter_CreatesValidDeformatter()
        {
            var deformatter = CreateDeformatter(GostECDsa512.Create());

            Assert.NotNull(deformatter);
            Assert.True(deformatter is GostECDsa512SignatureDeformatter);
        }

        [Fact]
        public void CreateFormatter_CreatesValidFormatter()
        {
            var formatter = CreateFormatter(GostECDsa512.Create());

            Assert.NotNull(formatter);
            Assert.True(formatter is GostECDsa512SignatureFormatter);
        }
    }
}
