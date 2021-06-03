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
    internal struct AlgorithmIdentifier
    {
        internal string Algorithm;
        internal ReadOnlyMemory<byte>? Parameters;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            try
            {
                writer.WriteObjectIdentifier(Algorithm);
            }
            catch (ArgumentException e)
            {
                throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
            }

            if (Parameters.HasValue)
            {
                try
                {
                    writer.WriteEncodedValue(Parameters.Value.Span);
                }
                catch (ArgumentException e)
                {
                    throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
                }
            }

            writer.PopSequence(tag);
        }

        [SecuritySafeCritical]
        internal static AlgorithmIdentifier Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static AlgorithmIdentifier Decode(
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
            out AlgorithmIdentifier decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(
            ref AsnValueReader reader,
            Asn1Tag expectedTag,
            ReadOnlyMemory<byte> rebind,
            out AlgorithmIdentifier decoded)
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
            out AlgorithmIdentifier decoded)
        {
            decoded = default;
            var sequenceReader = reader.ReadSequence(expectedTag);
            var rebindSpan = rebind.Span;
            decoded.Algorithm = sequenceReader.ReadObjectIdentifier();
            if (sequenceReader.HasData)
            {
                var tmpSpan = sequenceReader.ReadEncodedValue();
                decoded.Parameters =
                    rebindSpan.Overlaps(tmpSpan, out var offset) ?
                    rebind.Slice(offset, tmpSpan.Length) :
                    tmpSpan.ToArray();
            }
            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
