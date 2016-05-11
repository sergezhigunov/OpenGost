using Xunit;

namespace Gost.Security.Cryptography
{
    public class GostECDsaTests : AsymmetricAlgorithmTest<GostECDsa>
    {
        protected override GostECDsa Create()
            => new GostECDsaManaged();

        protected override byte[] SignHash(GostECDsa algorithm, byte[] hash)
            => algorithm.SignHash(hash);

        protected override bool VerifyHash(GostECDsa algorithm, byte[] hash, byte[] signature)
            => algorithm.VerifyHash(hash, signature);
    }
}