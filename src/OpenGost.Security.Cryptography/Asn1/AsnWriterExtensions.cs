using System.Formats.Asn1;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1;

internal static class AsnWriterExtensions
{
    internal static void WriteEncodedValueForCrypto(
        this AsnWriter writer,
        ReadOnlySpan<byte> value)
    {
        try
        {
            writer.WriteEncodedValue(value);
        }
        catch (ArgumentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
    }

    internal static void WriteObjectIdentifierForCrypto(
        this AsnWriter writer,
        string value)
    {
        try
        {
            writer.WriteObjectIdentifier(value);
        }
        catch (ArgumentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
    }

    internal static ArraySegment<byte> RentAndEncode(this AsnWriter writer)
    {
        byte[] rented = CryptoPool.Rent(writer.GetEncodedLength());
        int written = writer.Encode(rented);
        return new ArraySegment<byte>(rented, 0, written);
    }
}
