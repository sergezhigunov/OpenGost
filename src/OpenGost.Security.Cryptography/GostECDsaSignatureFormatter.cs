namespace OpenGost.Security.Cryptography;

internal sealed class GostECDsaSignatureFormatter : AsymmetricSignatureFormatter
{
    private GostECDsa? _key;

    public override byte[] CreateSignature(byte[] rgbHash)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);

        if (_key is null)
            throw new CryptographicUnexpectedOperationException();

        return _key.SignHash(rgbHash);
    }

    public override void SetHashAlgorithm(string strName)
    {
    }

    public override void SetKey(AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(key);

        _key = (GostECDsa)key;
    }
}
