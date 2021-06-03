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
    internal struct ECDomainParameters
    {
        internal SpecifiedECDomain? Specified;
        internal string? Named;

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false;
            if (Specified.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                Specified.Value.Encode(writer);
                wroteValue = true;
            }
            if (Named != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                try
                {
                    writer.WriteObjectIdentifier(Named);
                }
                catch (ArgumentException e)
                {
                    throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
                }
                wroteValue = true;
            }
            if (!wroteValue)
                throw new CryptographicException();
        }

        internal static ECDomainParameters Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            try
            {
                var reader = new AsnValueReader(encoded.Span, ruleSet);
                DecodeCore(ref reader, encoded, out var decoded);
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
            out ECDomainParameters decoded)
        {
            try
            {
                DecodeCore(ref reader, rebind, out decoded);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding, e);
            }
        }

        private static void DecodeCore(
            ref AsnValueReader reader,
            ReadOnlyMemory<byte> rebind,
            out ECDomainParameters decoded)
        {
            decoded = default;
            var tag = reader.PeekTag();
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                SpecifiedECDomain.Decode(ref reader, rebind, out var tmpSpecified);
                decoded.Specified = tmpSpecified;
            }
            else if (tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
                decoded.Named = reader.ReadObjectIdentifier();
            else
                throw new CryptographicException();
        }
    }
}
