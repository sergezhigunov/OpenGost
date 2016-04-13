using System;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public class HmacStreebog512Tests : HmacTest
    {
        protected override int BlockSize => 64;

        protected override HMAC Create()
            => new HMACStreebog512();

        protected override HashAlgorithm CreateHashAlgorithm()
            => Streebog512.Create();

        [Theory(DisplayName = nameof(Streebog512) + "_" + nameof(ComputeHmac), Skip = "No test cases available yet")]
        public void ComputeHmac(string dataHex, string keyHex, string expectedHmacHex)
            => VerifyHmac(dataHex, keyHex, expectedHmacHex);

        [Fact(DisplayName = nameof(Streebog512) + "_" + nameof(VerifyHmacRfc2104))]
        public new void VerifyHmacRfc2104()
            => base.VerifyHmacRfc2104();
    }
}