using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography.Asn1
{
    [SecuritySafeCritical]
    [StructLayout(LayoutKind.Sequential)]
    internal struct GostECDsaPublicKeyParameters
    {
        internal string PublicKeyParamSet;
        internal string? DigestParamSet;

        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }

        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);

            try
            {
                writer.WriteObjectIdentifier(PublicKeyParamSet);
            }
            catch (ArgumentException e)
            {
                throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
            }

            if (DigestParamSet != null)
            {
                try
                {
                    writer.WriteObjectIdentifier(DigestParamSet);
                }
                catch (ArgumentException e)
                {
                    throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
                }
            }

            writer.PopSequence(tag);
        }

        [SecuritySafeCritical]
        internal static GostECDsaPublicKeyParameters Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static GostECDsaPublicKeyParameters Decode(
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
            out GostECDsaPublicKeyParameters decoded)
        {
            Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
        }

        internal static void Decode(
            ref AsnValueReader reader,
            Asn1Tag expectedTag,
            ReadOnlyMemory<byte> rebind,
            out GostECDsaPublicKeyParameters decoded)
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

        [SuppressMessage("Style", "IDE0060:Remove unused parameter")]
        private static void DecodeCore(
            ref AsnValueReader reader,
            Asn1Tag expectedTag,
            ReadOnlyMemory<byte> rebind,
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
}
