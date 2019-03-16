using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    public abstract class AsymmetricAlgorithmTest<T>
        where T : AsymmetricAlgorithm, new()
    {
        protected T Create(string xmlString)
        {
            var algorithm = new T();
            algorithm.FromXmlString(xmlString);
            return algorithm;
        }
    }
}