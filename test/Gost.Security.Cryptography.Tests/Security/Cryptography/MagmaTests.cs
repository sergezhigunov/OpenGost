using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static TestsUtils;

    public class MagmaTests
    {
        private const string
            PlainText = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
            Key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

        private static byte[] KeyBytes { get; } = FromHexadecimal(Key);
        private static byte[] PlainTextBytes { get; } = FromHexadecimal(PlainText);

        [Theory(DisplayName = nameof(MagmaTests) + "_" + nameof(EncryptAndDecrypt))]
        [InlineData(CipherMode.ECB, PaddingMode.None, "1234567890abcdef234567890abcdef134567890abcdef12", "2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb")]
        [InlineData(CipherMode.CBC, PaddingMode.None, "1234567890abcdef234567890abcdef134567890abcdef12", "96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667")]
        [InlineData(CipherMode.CFB, PaddingMode.None, "1234567890abcdef234567890abcdef1", "db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505")]
        [InlineData(CipherMode.OFB, PaddingMode.None, "1234567890abcdef234567890abcdef1", "db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05")]
        public void EncryptAndDecrypt(CipherMode cipherMode, PaddingMode paddingMode, string iv, string expectedCipherText)
        {
            byte[]
                cipherTextBytes,
                newPlainTextBytes;

            using (var algorithm = new MagmaManaged { Mode = cipherMode, Padding = paddingMode, Key = KeyBytes, IV = FromHexadecimal(iv) })
                InternalEncryptAndDecrypt(
                    algorithm.CreateEncryptor,
                    algorithm.CreateDecryptor,
                    PlainTextBytes, out cipherTextBytes, out newPlainTextBytes);


            Assert.Equal(newPlainTextBytes.ToHexadecimalString(), PlainText);
            Assert.Equal(cipherTextBytes.ToHexadecimalString(), expectedCipherText);
        }
    }
}
