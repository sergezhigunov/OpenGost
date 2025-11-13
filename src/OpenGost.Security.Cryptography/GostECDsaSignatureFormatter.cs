namespace OpenGost.Security.Cryptography;

internal sealed class GostECDsaSignatureFormatter : AsymmetricSignatureFormatter
{
    private GostECDsa? _key;

    public override byte[] CreateSignature(byte[] rgbHash)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(rgbHash);
#else
        if (rgbHash is null) throw new ArgumentNullException(nameof(rgbHash));
#endif
        if (_key is null)
            throw new CryptographicUnexpectedOperationException();

        return _key.SignHash(rgbHash);
    }

    public override void SetHashAlgorithm(string strName)
    {
    }

    public override void SetKey(AsymmetricAlgorithm key)
    {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(key);
#else
        if (key is null) throw new ArgumentNullException(nameof(key));
#endif
        _key = (GostECDsa)key;
    }
}
