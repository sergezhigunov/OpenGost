using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    public class GostECDsa512SignatureDescriptionTests : SignatureDescriptionTest<GostECDsa512SignatureDescription>
    {
        protected override GostECDsa512SignatureDescription Create()
            => (GostECDsa512SignatureDescription)CreateFromName(GostECDsa512SignatureDescriptionFullName);

        [Fact(DisplayName = nameof(GostECDsa512SignatureDescriptionTests) + "_" + nameof(ValidateCreateDigest))]
        public void ValidateCreateDigest()
        {
            using (HashAlgorithm digest = CreateDigest())
            {
                Assert.NotNull(digest);
                Assert.True(digest is Streebog512);
            }
        }

        [Fact(DisplayName = nameof(GostECDsa512SignatureDescriptionTests) + "_" + nameof(ValidateCreateDeformatter))]
        public void ValidateCreateDeformatter()
        {
            AsymmetricSignatureDeformatter deformatter = CreateDeformatter(GostECDsa512.Create());

            Assert.NotNull(deformatter);
            Assert.True(deformatter is GostECDsa512SignatureDeformatter);
        }

        [Fact(DisplayName = nameof(GostECDsa512SignatureDescriptionTests) + "_" + nameof(ValidateCreateFormatter))]
        public void ValidateCreateFormatter()
        {
            AsymmetricSignatureFormatter formatter = CreateFormatter(GostECDsa512.Create());

            Assert.NotNull(formatter);
            Assert.True(formatter is GostECDsa512SignatureFormatter);
        }
    }
}
