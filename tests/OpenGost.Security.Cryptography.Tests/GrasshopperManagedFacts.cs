namespace OpenGost.Security.Cryptography.Tests;

public class GrasshopperFacts : SymmetricAlgorithmTest<GrasshopperManaged>
{
    private const string
        PlainText =
            "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
            "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
        Key = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        IV = "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819";

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


    public static object[][] Data { get; } =
    [
        [
            CipherMode.ECB,
            PaddingMode.None,
            PlainText,
            "7f679d90bebc24305a468d42b9d4edcdb429912c6e0032f9285452d76718d08b" +
            "f0ca33549d247ceef3f5a5313bd4b157d0b09ccde830b9eb3a02c4c5aa8ada98",
            Key,
            IV,
        ],
        [
            CipherMode.CBC,
            PaddingMode.None,
            PlainText,
            "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5ac" +
            "fe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970",
            Key,
            IV,
        ],
        [
            CipherMode.CFB,
            PaddingMode.None,
            PlainText,
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf" +
            "79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1",
            Key,
            IV,
        ],
        [
            CipherMode.OFB,
            PaddingMode.None,
            PlainText,
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf" +
            "66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150",
            Key,
            IV,
        ],
    ];
}


