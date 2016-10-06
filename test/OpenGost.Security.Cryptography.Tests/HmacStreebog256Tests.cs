using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class HmacStreebog256Tests : HmacTest<HMACStreebog256>
    {
        protected override int BlockSize => 64;

        protected override HashAlgorithm CreateHashAlgorithm()
            => new Streebog256Managed();

        [Theory(DisplayName = nameof(ComputeHmac))]
        [InlineData("0126bdb87800af214341456563780100",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")]
        public void ComputeHmac(string dataHex, string keyHex, string expectedHmacHex)
            => VerifyHmac(dataHex, keyHex, expectedHmacHex);

        [Fact(DisplayName = nameof(VerifyHmacRfc2104))]
        public new void VerifyHmacRfc2104()
            => base.VerifyHmacRfc2104();
    }
}