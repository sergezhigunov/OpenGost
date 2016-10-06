#if NET45
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    public abstract class SignatureDescriptionTest<T> : CryptoConfigRequiredTest
        where T : SignatureDescription, new()
    {
        protected HashAlgorithm CreateDigest()
            => new T().CreateDigest();

        protected AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
            => new T().CreateFormatter(key);

        protected AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
            => new T().CreateDeformatter(key);
    }
} 
#endif
