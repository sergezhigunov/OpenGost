using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1;

[SecuritySafeCritical]
[StructLayout(LayoutKind.Sequential)]
internal struct FieldID
{
    internal string FieldType;
    internal ReadOnlyMemory<byte> Parameters;

    internal void Encode(AsnWriter writer)
    {
        Encode(writer, Asn1Tag.Sequence);
    }

    internal void Encode(AsnWriter writer, Asn1Tag tag)
    {
        writer.PushSequence(tag);
        try
        {
            writer.WriteObjectIdentifier(FieldType);
        }
        catch (ArgumentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
        try
        {
            writer.WriteEncodedValue(Parameters.Span);
        }
        catch (ArgumentException e)
        {
            throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
        }
        writer.PopSequence(tag);
    }

    internal static FieldID Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        return Decode(Asn1Tag.Sequence, encoded, ruleSet);
    }

    internal static FieldID Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
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

    internal static void Decode(ref AsnValueReader reader, ReadOnlyMemory<byte> rebind, out FieldID decoded)
    {
        Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
    }

    internal static void Decode(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out FieldID decoded)
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
        out FieldID decoded)
    {
        decoded = default;
        var sequenceReader = reader.ReadSequence(expectedTag);
        var rebindSpan = rebind.Span;
        decoded.FieldType = sequenceReader.ReadObjectIdentifier();
        var tmpSpan = sequenceReader.ReadEncodedValue();
        decoded.Parameters =
            rebindSpan.Overlaps(tmpSpan, out var offset) ?
            rebind.Slice(offset, tmpSpan.Length) :
            tmpSpan.ToArray();
        sequenceReader.ThrowIfNotEmpty();
    }
}
