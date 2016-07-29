using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public abstract class AsymmetricAlgorithmTest<T> : CryptoConfigRequiredTest
        where T : AsymmetricAlgorithm
    {
        protected abstract T Create();

        protected T Create(string xmlString)
        {
            var algorithm = Create();
            algorithm.FromXmlString(xmlString);
            return algorithm;
        }
    }
}