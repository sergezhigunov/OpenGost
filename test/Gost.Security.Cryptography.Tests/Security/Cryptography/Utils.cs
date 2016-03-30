using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Gost.Security.Cryptography
{
    internal static class Utils
    {
        internal static byte[] ReadToEnd(this CryptoStream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            using (var memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }
        }

        internal static string ToHexadecimalString(this byte[] array)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));

            var builder = new StringBuilder(array.Length * 2);
            string hexAlphabet = "0123456789abcdef";
            foreach (byte b in array)
            {
                builder.Append(hexAlphabet[b >> 4]);
                builder.Append(hexAlphabet[b & 0x0F]);
            }
            return builder.ToString();
        }

        internal static byte[] FromHexadecimal(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            int textLength = text.Length;
            if (textLength % 2 != 0) throw new FormatException("Input text has incorrect format.");

            byte[] retval = new byte[textLength / 2];
            for (int i = 0, j = 0; i < textLength; i += 2, j++)
            {
                try
                {
                    retval[j] = (byte)((text[i].GetHexadecimalIndex() << 4) ^ text[i + 1].GetHexadecimalIndex());
                }
                catch (FormatException formatException)
                {
                    throw new FormatException("Input text has incorrect format.", formatException);
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
    }
}
