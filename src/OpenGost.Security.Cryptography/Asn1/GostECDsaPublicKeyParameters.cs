using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1;

[SecuritySafeCritical]
[StructLayout(LayoutKind.Sequential)]
internal struct GostECDsaPublicKeyParameters
{
    public string PublicKeyParamSet;
    public string? DigestParamSet;

    [SecuritySafeCritical]
    public static GostECDsaPublicKeyParameters Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        return Decode(Asn1Tag.Sequence, encoded, ruleSet);
    }

    public static GostECDsaPublicKeyParameters Decode(
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> encoded,
        AsnEncodingRules ruleSet)
    {
        try
        {
            var reader = new AsnValueReader(encoded.Span, ruleSet);
            DecodeCore(ref reader, expectedTag, out var decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
    }

    private static void DecodeCore(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        out GostECDsaPublicKeyParameters decoded)
    {
        decoded = default;
        var sequenceReader = reader.ReadSequence(expectedTag);
        decoded.PublicKeyParamSet = sequenceReader.ReadObjectIdentifier();
        if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
            decoded.DigestParamSet = sequenceReader.ReadObjectIdentifier();
        sequenceReader.ThrowIfNotEmpty();
    }
}
