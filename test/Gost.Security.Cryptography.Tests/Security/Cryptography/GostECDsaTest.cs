using Xunit;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    public abstract class GostECDsaTest : CryptoConfigRequiredTest
    {
        protected abstract GostECDsa Create(ECParameters parameters);

        protected bool VerifyHash(ECParameters parameters, byte[] hash, byte[] signature)
        {
            using (GostECDsa algorithm = Create(parameters))
                return algorithm.VerifyHash(hash, signature);
        }

        protected bool VerifyHash(ECParameters parameters, string hashHex, string signatureHex)
            => VerifyHash(parameters, hashHex.HexToByteArray(), signatureHex.HexToByteArray());

        protected void SignAndVerifyHash(ECParameters parameters)
        {
            byte[] hash, signature;
            using (GostECDsa algorithm = Create(parameters))
            {
                hash = GenerateRandomBytes(algorithm.KeySize / 8);
                signature = algorithm.SignHash(hash);
            }

            Assert.True(VerifyHash(parameters, hash, signature));
        }
    }
}
