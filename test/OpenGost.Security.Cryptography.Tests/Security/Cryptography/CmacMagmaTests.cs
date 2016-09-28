using Xunit;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConstants;

    public class CmacMagmaTests : CmacTest
    {
        protected override CMAC Create()
            => CMAC.Create(CMACMagmaAlgorithmFullName);

        [Theory(DisplayName = nameof(Magma) + "_" + nameof(ComputeCmac))]
        [InlineData(
            "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
            "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "154e72102030c5bb")]
        public void ComputeCmac(string dataHex, string keyHex, string expectedCmacHex)
            => VerifyCmac(dataHex, keyHex, expectedCmacHex);
    }
}
