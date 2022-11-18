namespace OpenGost.Security.Cryptography.Tests;

public class MagmaManagedFacts : SymmetricAlgorithmTest<MagmaManaged>
{
    private const string
        PlainText = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
        Key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    protected override int BlockSize => 64;

    [Theory]
    [MemberData(nameof(Data))]
    public override void Verify(
        CipherMode mode,
        PaddingMode padding,
        string plainText,
        string cipherText,
        string key,
        string iv)
        => base.Verify(mode, padding, plainText, cipherText, key, iv);

    public static object[][] Data { get; } = new[]
    {
        new object[]
        {
            CipherMode.ECB,
            PaddingMode.None,
            PlainText,
            "2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb",
            Key,
            "1234567890abcdef234567890abcdef134567890abcdef12",
        },
        new object[]
        {
            CipherMode.CBC,
            PaddingMode.None,
            PlainText,
            "96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667",
            Key,
            "1234567890abcdef234567890abcdef134567890abcdef12",
        },
        new object[]
        {
            CipherMode.CFB,
            PaddingMode.None,
            PlainText,
            "db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505",
            Key,
            "1234567890abcdef234567890abcdef1",
        },
        new object[]
        {
            CipherMode.OFB,
            PaddingMode.None,
            PlainText,
            "db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05",
            Key,
            "1234567890abcdef234567890abcdef1",
        },
    };
}
