using System;
using System.Formats.Asn1;
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
}
