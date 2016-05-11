using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public abstract class AsymmetricAlgorithmTest<T>
        where T : AsymmetricAlgorithm
    {
        protected abstract T Create();

        protected abstract byte[] SignHash(T algorithm, byte[] hash);

        protected abstract bool VerifyHash(T algorithm, byte[] hash, byte[] signature);

        protected T CreateFromXmlString(string xmlString)
        {
            var algorithm = Create();
            algorithm.FromXmlString(xmlString);
            return algorithm;
        }

        protected string CreateXmlString(bool includePrivateParameters)
        {
            using (var algorithm = Create())
                return algorithm.ToXmlString(includePrivateParameters);
        }

        protected byte[] SignHash(byte[] hash)
        {
            using (var algorithm = Create())
                return SignHash(algorithm, hash);
        }

        protected void VerifySignature(byte[] hash, byte[] signature, bool expectedResult)
        {
            using (var algorithm = Create())
                Assert.Equal(expectedResult, VerifyHash(algorithm, hash, signature));
        }
    }
}