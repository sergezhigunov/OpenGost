using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    public class GostECDsa256SignatureDescriptionTests : SignatureDescriptionTest<GostECDsa256SignatureDescription>
    {
        protected override GostECDsa256SignatureDescription Create()
            => (GostECDsa256SignatureDescription)CreateFromName(GostECDsa256SignatureDescriptionFullName);

        [Fact(DisplayName = nameof(GostECDsa256SignatureDescriptionTests) + "_" + nameof(ValidateCreateDigest))]
        public void ValidateCreateDigest()
        {
            using (HashAlgorithm digest = CreateDigest())
            {
                Assert.NotNull(digest);
                Assert.True(digest is Streebog256);
            }
        }

        [Fact(DisplayName = nameof(GostECDsa256SignatureDescriptionTests) + "_" + nameof(ValidateCreateDeformatter))]
        public void ValidateCreateDeformatter()
        {
            AsymmetricSignatureDeformatter deformatter = CreateDeformatter(GostECDsa256.Create());

            Assert.NotNull(deformatter);
            Assert.True(deformatter is GostECDsa256SignatureDeformatter);
        }

        [Fact(DisplayName = nameof(GostECDsa256SignatureDescriptionTests) + "_" + nameof(ValidateCreateFormatter))]
        public void ValidateCreateFormatter()
        {
            AsymmetricSignatureFormatter formatter = CreateFormatter(GostECDsa256.Create());

            Assert.NotNull(formatter);
            Assert.True(formatter is GostECDsa256SignatureFormatter);
        }
    }
}
