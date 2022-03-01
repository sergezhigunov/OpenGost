using System;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

internal class GostECDsaSignatureFormatter :  AsymmetricSignatureFormatter
{
    private GostECDsa? _key;

    public override byte[] CreateSignature(byte[] rgbHash)
    {
        if (rgbHash == null)
            throw new ArgumentNullException(nameof(rgbHash));
        if (_key == null)
            throw new CryptographicUnexpectedOperationException();

        return _key.SignHash(rgbHash);
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
