using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

internal class GostECDsaSignatureDeformatter : AsymmetricSignatureDeformatter
{
    private GostECDsa? _key;

    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
    {
        if (rgbHash == null)
            throw new ArgumentNullException(nameof(rgbHash));
        if (rgbSignature is null)
            throw new ArgumentNullException(nameof(rgbSignature));
        if (_key == null)
            throw new CryptographicUnexpectedOperationException();

        return _key.VerifyHash(rgbHash, rgbSignature);
    }

    public override void SetHashAlgorithm(string strName)
    {
    }

    public override void SetKey(AsymmetricAlgorithm key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        _key = (GostECDsa)key;
    }
}
