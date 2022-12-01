﻿namespace OpenGost.Security.Cryptography.Tests;

public class CmacGrasshopperFacts : CmacTest<CMACGrasshopper>
{
    public override int HashSize => 128;

    [Theory]
    [InlineData(
        "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
        "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        "336f4d296059fbe34ddeb35b37749c67")]
    public override void VerifyCmac(string dataHex, string keyHex, string expectedCmacHex)
        => base.VerifyCmac(dataHex, keyHex, expectedCmacHex);
}
