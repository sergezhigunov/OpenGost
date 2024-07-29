#if !NET6_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;

namespace OpenGost.Security.Cryptography.Tests;

[ExcludeFromCodeCoverage]
internal static class Convert
{
    public static byte[] FromHexString(this string s)
    {
        if (s is null)
            throw new ArgumentNullException(nameof(s));
        var hexStringLength = s.Length;
        if (hexStringLength % 2 != 0)
            throw CreateTextIncorrectFormatException(null);

        var retval = new byte[hexStringLength / 2];
        for (int i = 0, j = 0; i < hexStringLength; i += 2, j++)
        {
            try
            {
                retval[j] = (byte)
                    ((s[i].GetHexadecimalIndex() << 4) ^
                    s[i + 1].GetHexadecimalIndex());
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
            return (byte)(character - 'a' + 10);
        else if (character >= 'A' && character <= 'F')
            return (byte)(character - 'A' + 10);
        throw new FormatException($"Invalid character '{character}'.");
    }

    private static FormatException CreateTextIncorrectFormatException(Exception? innerException)
        => new("Input text has incorrect format.", innerException);
}
#endif
