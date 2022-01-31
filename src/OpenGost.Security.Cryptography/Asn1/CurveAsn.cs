using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1;

[SecuritySafeCritical]
[StructLayout(LayoutKind.Sequential)]
internal struct CurveAsn
{
    public ReadOnlyMemory<byte> A;
    public ReadOnlyMemory<byte> B;
    public ReadOnlyMemory<byte>? Seed;

    public void Encode(AsnWriter writer)
    {
        Encode(writer, Asn1Tag.Sequence);
    }

    public void Encode(AsnWriter writer, Asn1Tag tag)
    {
        writer.PushSequence(tag);
        writer.WriteOctetString(A.Span);
        writer.WriteOctetString(B.Span);
        if (Seed.HasValue)
            writer.WriteBitString(Seed.Value.Span, 0);
        writer.PopSequence(tag);
    }

    public static CurveAsn Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        return Decode(Asn1Tag.Sequence, encoded, ruleSet);
    }

    public static CurveAsn Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        try
        {
            var reader = new AsnValueReader(encoded.Span, ruleSet);
            DecodeCore(ref reader, expectedTag, encoded, out var decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
    }

    public static void Decode(ref AsnValueReader reader, ReadOnlyMemory<byte> rebind, out CurveAsn decoded)
    {
        Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
    }

    public static void Decode(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out CurveAsn decoded)
    {
        try
        {
            DecodeCore(ref reader, expectedTag, rebind, out decoded);
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
    }

    private static void DecodeCore(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out CurveAsn decoded)
    {
        decoded = default;
        var sequenceReader = reader.ReadSequence(expectedTag);
        var rebindSpan = rebind.Span;
        int offset;
        if (sequenceReader.TryReadPrimitiveOctetString(out var tmpSpan))
            decoded.A =
                rebindSpan.Overlaps(tmpSpan, out offset) ?
                rebind.Slice(offset, tmpSpan.Length) :
                tmpSpan.ToArray();
        else
            decoded.A = sequenceReader.ReadOctetString();
        if (sequenceReader.TryReadPrimitiveOctetString(out tmpSpan))
            decoded.B =
                rebindSpan.Overlaps(tmpSpan, out offset) ?
                rebind.Slice(offset, tmpSpan.Length) :
                tmpSpan.ToArray();
        else
            decoded.B = sequenceReader.ReadOctetString();
        if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveBitString))
        {
            if (sequenceReader.TryReadPrimitiveBitString(out _, out tmpSpan))
                decoded.Seed =
                    rebindSpan.Overlaps(tmpSpan, out offset) ?
                    rebind.Slice(offset, tmpSpan.Length) :
                    tmpSpan.ToArray();
            else
                decoded.Seed = sequenceReader.ReadBitString(out _);
        }
        sequenceReader.ThrowIfNotEmpty();
    }
}
