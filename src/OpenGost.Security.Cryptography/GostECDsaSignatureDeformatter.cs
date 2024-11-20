namespace OpenGost.Security.Cryptography;

internal sealed class GostECDsaSignatureDeformatter : AsymmetricSignatureDeformatter
{
    private GostECDsa? _key;

    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
    {
        ArgumentNullException.ThrowIfNull(rgbHash);
        ArgumentNullException.ThrowIfNull(rgbSignature);

        if (_key is null)
            throw new CryptographicUnexpectedOperationException();

        return _key.VerifyHash(rgbHash, rgbSignature);
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
