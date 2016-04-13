using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public class HmacStreebog256Tests : HmacTest
    {
        protected override int BlockSize => 64;

        protected override HMAC Create()
            => new HMACStreebog256();

        protected override HashAlgorithm CreateHashAlgorithm()
            => Streebog256.Create();

        [Theory(DisplayName = nameof(Streebog256) + "_" + nameof(ComputeHmac), Skip = "No test cases avaliable yet")]
        public void ComputeHmac(string dataHex, string keyHex, string expectedHmacHex)
            => VerifyHmac(dataHex, keyHex, expectedHmacHex);

        [Fact(DisplayName = nameof(Streebog256) + "_" + nameof(VerifyHmacRfc2104))]
        public new void VerifyHmacRfc2104()
            => base.VerifyHmacRfc2104();
    }
}