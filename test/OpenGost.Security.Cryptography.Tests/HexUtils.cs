using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace OpenGost.Security.Cryptography
{
#if NET45
    [ExcludeFromCodeCoverage] 
#endif
    internal static class HexUtils
    {
        private static readonly string HexAlphabet = "0123456789abcdef";

        internal static byte[] HexToByteArray(this string hexString)
        {
            if (hexString == null) throw new ArgumentNullException(nameof(hexString));
            int hexStringLength = hexString.Length;
            if (hexStringLength % 2 != 0) throw CreateTextIncorrectFormatException(null);

            byte[] retval = new byte[hexStringLength / 2];
            for (int i = 0, j = 0; i < hexStringLength; i += 2, j++)
            {
                try
                {
                    retval[j] = (byte)
                        ((hexString[i].GetHexadecimalIndex() << 4) ^
                        hexString[i + 1].GetHexadecimalIndex());
                }
                catch (FormatException formatException)
                {
                    throw CreateTextIncorrectFormatException(formatException);
                }
            }
            return retval;
        }

        internal static string ToHexString(this byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));

            var builder = new StringBuilder(bytes.Length * 2);

            foreach (byte b in bytes)
            {
                builder.Append(HexAlphabet[b >> 4]);
                builder.Append(HexAlphabet[b & 0x0F]);
            }
            return builder.ToString();
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

        private static FormatException CreateTextIncorrectFormatException(Exception innerException)
            => new FormatException("Input text has incorrect format.", innerException);
    }
}
