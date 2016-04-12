using System;
using System.IO;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    internal static class TestsUtils
    {
        internal static void InternalEncryptAndDecrypt(
            Func<ICryptoTransform> encryptorFactory,
            Func<ICryptoTransform> decryptorFactory,
            byte[] plainText,
            out byte[] cipherText,
            out byte[] newPlainText)
        {
            cipherText = InternalTransform(encryptorFactory, plainText);
            newPlainText = InternalTransform(decryptorFactory, cipherText);
        }

        internal static byte[] InternalTransform(Func<ICryptoTransform> factory, byte[] input)
        {
            using (var memoryStream = new MemoryStream())
            using (var transform = factory())
            using (var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, 0, input.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }
    }
}
