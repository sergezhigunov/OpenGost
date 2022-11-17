using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class HmacStreebog512Facts : HmacTest<HMACStreebog512>
{
    protected override int BlockSize => 64;

    protected override HashAlgorithm CreateHashAlgorithm()
        => Streebog512.Create();

    [Theory]
    [InlineData("0126bdb87800af214341456563780100",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77" +
        "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6")]
    public void ComputeHmac(string dataHex, string keyHex, string expectedHmacHex)
        => VerifyHmac(dataHex, keyHex, expectedHmacHex);

    [Fact]
    public override void VerifyHmacRfc2104()
        => base.VerifyHmacRfc2104();
}
