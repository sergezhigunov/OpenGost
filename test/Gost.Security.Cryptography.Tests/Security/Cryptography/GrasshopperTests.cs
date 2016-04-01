using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static TestsUtils;

    public class GrasshopperTests
    {
        private const string
            PlainText = "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011",
            Key = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
            IV = "1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819";

        private static byte[] KeyBytes { get; } = FromHexadecimal(Key);
        private static byte[] PlainTextBytes { get; } = FromHexadecimal(PlainText);
        private static byte[] IVBytes { get; } = FromHexadecimal(IV);

        [Theory(DisplayName = nameof(GrasshopperTests) + "_" + nameof(EncryptAndDecrypt))]
        [InlineData(CipherMode.ECB, PaddingMode.None, "7f679d90bebc24305a468d42b9d4edcdb429912c6e0032f9285452d76718d08bf0ca33549d247ceef3f5a5313bd4b157d0b09ccde830b9eb3a02c4c5aa8ada98")]
        [InlineData(CipherMode.CBC, PaddingMode.None, "689972d4a085fa4d90e52e3d6d7dcc272826e661b478eca6af1e8e448d5ea5acfe7babf1e91999e85640e8b0f49d90d0167688065a895c631a2d9a1560b63970")]
        [InlineData(CipherMode.CFB, PaddingMode.None, "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf79f2a8eb5cc68d38842d264e97a238b54ffebecd4e922de6c75bd9dd44fbf4d1")]
        [InlineData(CipherMode.OFB, PaddingMode.None, "81800a59b1842b24ff1f795e897abd95ed5b47a7048cfab48fb521369d9326bf66a257ac3ca0b8b1c80fe7fc10288a13203ebbc066138660a0292243f6903150")]
        public void EncryptAndDecrypt(CipherMode cipherMode, PaddingMode paddingMode, string expectedCipherText)
        {
            byte[]
                cipherTextBytes,
                newPlainTextBytes;

            using (var algorithm = new GrasshopperManaged { Mode = cipherMode, Padding = paddingMode, Key = KeyBytes, IV = IVBytes })
            {
                using (var cipherTextEncryptStream = new MemoryStream())
                using (var encryptor = algorithm.CreateEncryptor())
                using (var encryptorStream = new CryptoStream(cipherTextEncryptStream, encryptor, CryptoStreamMode.Write))
                {
                    encryptorStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                    encryptorStream.FlushFinalBlock();
                    cipherTextBytes = cipherTextEncryptStream.ToArray();
                }
                using (var cipherTextDecryptStream = new MemoryStream(cipherTextBytes, false))
                using (var decryptor = algorithm.CreateDecryptor())
                using (var decryptorStream = new CryptoStream(cipherTextDecryptStream, decryptor, CryptoStreamMode.Read))
                {
                    newPlainTextBytes = decryptorStream.ReadToEnd();
                }
            }

            Assert.Equal(newPlainTextBytes.ToHexadecimalString(), PlainText);
            Assert.Equal(cipherTextBytes.ToHexadecimalString(), expectedCipherText);
        }
    }
}
