using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security;

namespace OpenGost.Security.Cryptography.Asn1
{
    [SecuritySafeCritical]
    internal ref struct AsnValueReader
    {
        private static readonly byte[] _singleByte = new byte[1];

        private ReadOnlySpan<byte> _span;
        private readonly AsnEncodingRules _ruleSet;

        internal AsnValueReader(ReadOnlySpan<byte> span, AsnEncodingRules ruleSet)
        {
            _span = span;
            _ruleSet = ruleSet;
        }

        internal bool HasData => !_span.IsEmpty;

        internal void ThrowIfNotEmpty()
        {
            if (!_span.IsEmpty)
            {
                new AsnReader(_singleByte, _ruleSet).ThrowIfNotEmpty();
            }
        }

        internal Asn1Tag PeekTag()
        {
            return Asn1Tag.Decode(_span, out _);
        }

        internal ReadOnlySpan<byte> PeekEncodedValue()
        {
            AsnDecoder.ReadEncodedValue(_span, _ruleSet, out _, out _, out int consumed);
            return _span.Slice(0, consumed);
        }

        internal ReadOnlySpan<byte> ReadEncodedValue()
        {
            var value = PeekEncodedValue();
            _span = _span.Slice(value.Length);
            return value;
        }

        internal bool ReadBoolean(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadBoolean(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal BigInteger ReadInteger(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadInteger(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal bool TryReadInt32(out int value, Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.TryReadInt32(_span, _ruleSet, out value, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal ReadOnlySpan<byte> ReadIntegerBytes(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadIntegerBytes(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal bool TryReadPrimitiveBitString(
            out int unusedBitCount,
            out ReadOnlySpan<byte> value,
            Asn1Tag? expectedTag = default)
        {
            bool ret = AsnDecoder.TryReadPrimitiveBitString(
                _span,
                _ruleSet,
                out unusedBitCount,
                out value,
                out int consumed,
                expectedTag);

            _span = _span.Slice(consumed);
            return ret;
        }

        internal byte[] ReadBitString(out int unusedBitCount, Asn1Tag? expectedTag = default)
        {
            byte[] ret = AsnDecoder.ReadBitString(
                _span,
                _ruleSet,
                out unusedBitCount,
                out int consumed,
                expectedTag);

            _span = _span.Slice(consumed);
            return ret;
        }

        internal T ReadNamedBitListValue<T>(Asn1Tag? expectedTag = default)
            where T : Enum
        {
            var ret = AsnDecoder.ReadNamedBitListValue<T>(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal bool TryReadPrimitiveOctetString(
            out ReadOnlySpan<byte> value,
            Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.TryReadPrimitiveOctetString(
                _span,
                _ruleSet,
                out value,
                out int consumed,
                expectedTag);

            _span = _span.Slice(consumed);
            return ret;
        }

        internal byte[] ReadOctetString(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadOctetString(
                _span,
                _ruleSet,
                out int consumed,
                expectedTag);

            _span = _span.Slice(consumed);
            return ret;
        }

        internal string ReadObjectIdentifier(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadObjectIdentifier(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal AsnValueReader ReadSequence(Asn1Tag? expectedTag = default)
        {
            AsnDecoder.ReadSequence(
                _span,
                _ruleSet,
                out int contentOffset,
                out int contentLength,
                out int bytesConsumed,
                expectedTag);

            var content = _span.Slice(contentOffset, contentLength);
            _span = _span.Slice(bytesConsumed);
            return new AsnValueReader(content, _ruleSet);
        }

        internal AsnValueReader ReadSetOf(Asn1Tag? expectedTag = default)
        {
            AsnDecoder.ReadSetOf(
                _span,
                _ruleSet,
                out int contentOffset,
                out int contentLength,
                out int bytesConsumed,
                expectedTag: expectedTag);

            var content = _span.Slice(contentOffset, contentLength);
            _span = _span.Slice(bytesConsumed);
            return new AsnValueReader(content, _ruleSet);
        }

        internal DateTimeOffset ReadUtcTime(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadUtcTime(_span, _ruleSet, out int consumed, expectedTag: expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal DateTimeOffset ReadGeneralizedTime(Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadGeneralizedTime(_span, _ruleSet, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }

        internal string ReadCharacterString(UniversalTagNumber encodingType, Asn1Tag? expectedTag = default)
        {
            var ret = AsnDecoder.ReadCharacterString(_span, _ruleSet, encodingType, out int consumed, expectedTag);
            _span = _span.Slice(consumed);
            return ret;
        }
    }
}
