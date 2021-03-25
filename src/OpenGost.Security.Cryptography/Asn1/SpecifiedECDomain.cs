using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1
{
    [SecuritySafeCritical]
    [StructLayout(LayoutKind.Sequential)]
    internal struct SpecifiedECDomain
    {
        internal int Version;
        internal FieldID FieldID;
        internal CurveAsn Curve;
        internal ReadOnlyMemory<byte> Base;
        internal ReadOnlyMemory<byte> Order;
        internal ReadOnlyMemory<byte>? Cofactor;
        internal string? Hash;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            writer.WriteInteger(Version);
            FieldID.Encode(writer);
            Curve.Encode(writer);
            writer.WriteOctetString(Base.Span);
            writer.WriteInteger(Order.Span);
            if (Cofactor.HasValue)
                writer.WriteInteger(Cofactor.Value.Span);
            if (Hash != null)
            {
                try
                {
                    writer.WriteObjectIdentifier(Hash);
                }
                catch (ArgumentException e)
                {
                    throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
                }
            }
            writer.PopSequence(tag);
        }

        internal static SpecifiedECDomain Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static SpecifiedECDomain Decode(
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

        internal static void Decode(
            ref AsnValueReader reader,
            ReadOnlyMemory<byte> rebind,
            out SpecifiedECDomain decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(
            ref AsnValueReader reader,
            Asn1Tag expectedTag, ReadOnlyMemory<byte> rebind,
            out SpecifiedECDomain decoded)
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
            out SpecifiedECDomain decoded)
        {
            decoded = default;
            var sequenceReader = reader.ReadSequence(expectedTag);
            var rebindSpan = rebind.Span;
            int offset;
            if (!sequenceReader.TryReadInt32(out decoded.Version))
                sequenceReader.ThrowIfNotEmpty();
            FieldID.Decode(ref sequenceReader, rebind, out decoded.FieldID);
            CurveAsn.Decode(ref sequenceReader, rebind, out decoded.Curve);
            if (sequenceReader.TryReadPrimitiveOctetString(out var tmpSpan))
                decoded.Base =
                    rebindSpan.Overlaps(tmpSpan, out offset) ?
                    rebind.Slice(offset, tmpSpan.Length) :
                    tmpSpan.ToArray();
            else
                decoded.Base = sequenceReader.ReadOctetString();
            tmpSpan = sequenceReader.ReadIntegerBytes();
            decoded.Order =
                rebindSpan.Overlaps(tmpSpan, out offset) ?
                rebind.Slice(offset, tmpSpan.Length) :
                tmpSpan.ToArray();
            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                tmpSpan = sequenceReader.ReadIntegerBytes();
                decoded.Cofactor =
                    rebindSpan.Overlaps(tmpSpan, out offset) ?
                    rebind.Slice(offset, tmpSpan.Length) :
                    tmpSpan.ToArray();
            }
            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
                decoded.Hash = sequenceReader.ReadObjectIdentifier();
            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
