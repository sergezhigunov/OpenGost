namespace OpenGost.Security.Cryptography;

internal sealed class GostECDsaSignatureDeformatter : AsymmetricSignatureDeformatter
{
    private GostECDsa? _key;

    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(rgbHash);
        ArgumentNullException.ThrowIfNull(rgbSignature);
#else
        if (rgbHash is null) throw new ArgumentNullException(nameof(rgbHash));
        if (rgbSignature is null) throw new ArgumentNullException(nameof(rgbSignature));
#endif
        if (_key is null)
            throw new CryptographicUnexpectedOperationException();

        return _key.VerifyHash(rgbHash, rgbSignature);
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
