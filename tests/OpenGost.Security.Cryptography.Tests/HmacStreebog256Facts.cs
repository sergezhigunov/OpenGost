namespace OpenGost.Security.Cryptography.Tests;

public class HmacStreebog256Facts : HmacTest<HMACStreebog256>
{
    protected override HashAlgorithm CreateHashAlgorithm()
        => Streebog256.Create();

    protected override HMACStreebog256 CreateHMAC(byte[] key)
        => new(key);

    [Theory]
    [InlineData("0126bdb87800af214341456563780100",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")]
    public override void VerifyHmac(string dataHex, string keyHex, string expectedHmacHex)
        => base.VerifyHmac(dataHex, keyHex, expectedHmacHex);
}
