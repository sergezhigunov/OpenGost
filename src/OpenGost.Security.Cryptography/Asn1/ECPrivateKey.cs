using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1;

[SecuritySafeCritical]
[StructLayout(LayoutKind.Sequential)]
internal struct ECPrivateKey
{
    public int Version;
    public ReadOnlyMemory<byte> PrivateKey;
    public ECDomainParameters? Parameters;
    public ReadOnlyMemory<byte>? PublicKey;

    public void Encode(AsnWriter writer)
    {
        Encode(writer, Asn1Tag.Sequence);
    }

    public void Encode(AsnWriter writer, Asn1Tag tag)
    {
        writer.PushSequence(tag);
        writer.WriteInteger(Version);
        writer.WriteOctetString(PrivateKey.Span);
        if (Parameters.HasValue)
        {
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            Parameters.Value.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        if (PublicKey.HasValue)
        {
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteBitString(PublicKey.Value.Span, 0);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
        }
        writer.PopSequence(tag);
    }

    public static ECPrivateKey Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        return Decode(Asn1Tag.Sequence, encoded, ruleSet);
    }

    public static ECPrivateKey Decode(
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> encoded,
        AsnEncodingRules ruleSet)
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

    public static void Decode(ref AsnValueReader reader, ReadOnlyMemory<byte> rebind, out ECPrivateKey decoded)
    {
        Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
    }

    public static void Decode(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out ECPrivateKey decoded)
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
        out ECPrivateKey decoded)
    {
        decoded = default;
        var sequenceReader = reader.ReadSequence(expectedTag);
        var rebindSpan = rebind.Span;
        int offset;
        if (!sequenceReader.TryReadInt32(out decoded.Version))
            sequenceReader.ThrowIfNotEmpty();
        if (sequenceReader.TryReadPrimitiveOctetString(out var tmpSpan))
            decoded.PrivateKey =
                rebindSpan.Overlaps(tmpSpan, out offset) ?
                rebind.Slice(offset, tmpSpan.Length) :
                tmpSpan.ToArray();
        else
            decoded.PrivateKey = sequenceReader.ReadOctetString();
        AsnValueReader explicitReader;
        if (sequenceReader.HasData && sequenceReader.PeekTag()
            .HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            ECDomainParameters.Decode(ref explicitReader, rebind, out var tmpParameters);
            decoded.Parameters = tmpParameters;
            explicitReader.ThrowIfNotEmpty();
        }
        if (sequenceReader.HasData && sequenceReader.PeekTag()
            .HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            if (explicitReader.TryReadPrimitiveBitString(out _, out tmpSpan))
                decoded.PublicKey =
                    rebindSpan.Overlaps(tmpSpan, out offset) ?
                    rebind.Slice(offset, tmpSpan.Length) :
                    tmpSpan.ToArray();
            else
                decoded.PublicKey = explicitReader.ReadBitString(out _);
            explicitReader.ThrowIfNotEmpty();
        }
        sequenceReader.ThrowIfNotEmpty();
    }
}
