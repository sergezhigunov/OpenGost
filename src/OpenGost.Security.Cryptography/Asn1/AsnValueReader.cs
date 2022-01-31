using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security;

namespace OpenGost.Security.Cryptography.Asn1;

[SecuritySafeCritical]
internal ref struct AsnValueReader
{
    private static readonly byte[] _singleByte = new byte[1];

    private ReadOnlySpan<byte> _span;
    private readonly AsnEncodingRules _ruleSet;

    public AsnValueReader(ReadOnlySpan<byte> span, AsnEncodingRules ruleSet)
    {
        _span = span;
        _ruleSet = ruleSet;
    }

    public bool HasData => !_span.IsEmpty;

    public void ThrowIfNotEmpty()
    {
        if (!_span.IsEmpty)
        {
            new AsnReader(_singleByte, _ruleSet).ThrowIfNotEmpty();
        }
    }

    public Asn1Tag PeekTag()
    {
        return Asn1Tag.Decode(_span, out _);
    }

    public ReadOnlySpan<byte> PeekEncodedValue()
    {
        AsnDecoder.ReadEncodedValue(_span, _ruleSet, out _, out _, out int consumed);
        return _span.Slice(0, consumed);
    }

    public ReadOnlySpan<byte> ReadEncodedValue()
    {
        var value = PeekEncodedValue();
        _span = _span.Slice(value.Length);
        return value;
    }

    public bool ReadBoolean(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadBoolean(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public BigInteger ReadInteger(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadInteger(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public bool TryReadInt32(out int value, Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.TryReadInt32(_span, _ruleSet, out value, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public ReadOnlySpan<byte> ReadIntegerBytes(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadIntegerBytes(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public bool TryReadPrimitiveBitString(
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

    public byte[] ReadBitString(out int unusedBitCount, Asn1Tag? expectedTag = default)
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

    public T ReadNamedBitListValue<T>(Asn1Tag? expectedTag = default)
        where T : Enum
    {
        var ret = AsnDecoder.ReadNamedBitListValue<T>(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public bool TryReadPrimitiveOctetString(
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

    public byte[] ReadOctetString(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadOctetString(
            _span,
            _ruleSet,
            out int consumed,
            expectedTag);

        _span = _span.Slice(consumed);
        return ret;
    }

    public string ReadObjectIdentifier(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadObjectIdentifier(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public AsnValueReader ReadSequence(Asn1Tag? expectedTag = default)
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

    public AsnValueReader ReadSetOf(Asn1Tag? expectedTag = default)
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

    public DateTimeOffset ReadUtcTime(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadUtcTime(_span, _ruleSet, out int consumed, expectedTag: expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public DateTimeOffset ReadGeneralizedTime(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadGeneralizedTime(_span, _ruleSet, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    public string ReadCharacterString(UniversalTagNumber encodingType, Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadCharacterString(_span, _ruleSet, encodingType, out int consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }
}
