namespace OpenGost.Security.Cryptography.X509Certificates
{
    internal enum AsnTag
    {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        BmpString = 0x1e,
        IA5String = 0x16,
        PrintableString = 0x13,
        TeletexString = 0x14,
        Utf8String = 0x0C,
        Sequence = 0x30,
        Set = 0x31,
    }
}
