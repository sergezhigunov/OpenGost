using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Gost.Security.Cryptography
{
    internal static class TestsUtils
    {
        private static readonly string HexadecimalAlphabet = "0123456789abcdef";

        internal static string ToHexadecimalStringLittleEndian(this byte[] array)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));

            var builder = new StringBuilder(array.Length * 2);

            foreach (byte b in array)
            {
                builder.Append(HexadecimalAlphabet[b >> 4]);
                builder.Append(HexadecimalAlphabet[b & 0x0F]);
            }
            return builder.ToString();
        }

        internal static string ToHexadecimalStringBigEndian(this byte[] array)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));

            var builder = new StringBuilder(array.Length * 2);

            for (int i = array.Length - 1; i >= 0; i--)
            {
                byte b = array[i];
                builder.Append(HexadecimalAlphabet[b >> 4]);
                builder.Append(HexadecimalAlphabet[b & 0x0F]);
            }
            return builder.ToString();
        }

        internal static byte[] FromHexadecimalLittleEndian(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            int textLength = text.Length;
            if (textLength % 2 != 0) throw CreateTextIncorrectFormatException(null);

            byte[] retval = new byte[textLength / 2];
            for (int i = 0, j = 0; i < textLength; i += 2, j++)
            {
                try
                {
                    retval[j] = (byte)((text[i].GetHexadecimalIndex() << 4) ^ text[i + 1].GetHexadecimalIndex());
                }
                catch (FormatException formatException)
                {
                    throw CreateTextIncorrectFormatException(formatException);
                }
            }
            return retval;
        }

        internal static byte[] FromHexadecimalBigEndian(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            int textLength = text.Length;
            if (textLength % 2 != 0) throw CreateTextIncorrectFormatException(null);

            byte[] retval = new byte[textLength / 2];
            for (int i = 0, j = textLength / 2 - 1; i < textLength; i += 2, j--)
            {
                try
                {
                    retval[j] = (byte)((text[i].GetHexadecimalIndex() << 4) ^ text[i + 1].GetHexadecimalIndex());
                }
                catch (FormatException formatException)
                {
                    throw CreateTextIncorrectFormatException(formatException);
                }
            }
            return retval;
        }

        private static byte GetHexadecimalIndex(this char character)
        {
            if (character >= '0' && character <= '9')
                return (byte)(character - '0');
            else if (character >= 'a' && character <= 'f')
                return (byte)((character - 'a') + 10);
            else if (character >= 'A' && character <= 'F')
                return (byte)((character - 'A') + 10);
            throw new FormatException($"Invalid character '{character}'.");
        }

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

        private static FormatException CreateTextIncorrectFormatException(Exception innerException)
            => new FormatException("Input text has incorrect format.", innerException);
    }
}
