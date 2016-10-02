using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    public abstract class SignatureDescriptionTest<T> : CryptoConfigRequiredTest
        where T : SignatureDescription
    {
        protected abstract T Create();

        protected HashAlgorithm CreateDigest()
            => Create().CreateDigest();

        protected AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
            => Create().CreateFormatter(key);

        protected AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
            => Create().CreateDeformatter(key);
    }
}
