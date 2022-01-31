using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography.Tests;

public abstract class SignatureDescriptionTest<T> : CryptoConfigRequiredTest
    where T : SignatureDescription, new()
{
    protected HashAlgorithm? CreateDigest()
        => new T().CreateDigest();
}
