using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public abstract class SymmetricAlgorithmTest<T>
        where T : SymmetricAlgorithm, new()
    {
        protected void Verify(CipherMode mode, PaddingMode padding, string plainTextHex, string cipherTextHex, string keyHex, string ivHex)
        {
            byte[]
                plainTextBytes = plainTextHex.HexToByteArray(),
                keyBytes = keyHex.HexToByteArray(),
                ivBytes = ivHex.HexToByteArray();

            using (var algorithm = new T { Mode = mode, Padding = padding, Key = keyBytes, IV = ivBytes })
            {
                byte[] encryptedBytes;
                var input = new MemoryStream(plainTextBytes);
                using (CryptoStream cryptoStream = new CryptoStream(input, algorithm.CreateEncryptor(), CryptoStreamMode.Read))
                using (MemoryStream output = new MemoryStream())
                {
                    cryptoStream.CopyTo(output);
                    encryptedBytes = output.ToArray();
                }

                Assert.NotEqual(plainTextBytes, encryptedBytes);

                byte[] cipherTextBytes = cipherTextHex.HexToByteArray();

                Assert.Equal(cipherTextBytes, encryptedBytes);

                byte[] decryptedBytes;
                input = new MemoryStream(encryptedBytes);
                using (CryptoStream cryptoStream = new CryptoStream(input, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                using (MemoryStream output = new MemoryStream())
                {
                    cryptoStream.CopyTo(output);
                    decryptedBytes = output.ToArray();
                }

                Assert.Equal(plainTextBytes, decryptedBytes);
            }
        }
    }
}
