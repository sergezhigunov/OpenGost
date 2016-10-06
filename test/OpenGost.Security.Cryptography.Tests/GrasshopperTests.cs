using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class GrasshopperTests : SymmetricAlgorithmTest<GrasshopperManaged>
    {
        private const string
            PlainText = "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            Key = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
            IV = "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819";

        [Theory(DisplayName = nameof(Grasshopper) + "_" + nameof(EncryptAndDecrypt))]
        [InlineData(CipherMode.ECB, PaddingMode.None,
            "7f679d90bebc24305a468d42b9d4edcdb429912c6e0032f9285452d76718d08bf0ca33549d247ceef3f5a5313bd4b157d0b09ccde830b9eb3a02c4c5aa8ada98")]
        [InlineData(CipherMode.CBC, PaddingMode.None,
            "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970")]
#if NET45
        [InlineData(CipherMode.CFB, PaddingMode.None,
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1")]
        [InlineData(CipherMode.OFB, PaddingMode.None,
            "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150")] 
#endif
        public void EncryptAndDecrypt(CipherMode mode, PaddingMode padding, string cipherText)
            => Verify(mode, padding, PlainText, cipherText, Key, IV);
    }
}
