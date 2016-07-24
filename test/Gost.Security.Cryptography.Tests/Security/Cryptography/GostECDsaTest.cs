using Xunit;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;
    using static ECHelper;

    public abstract class GostECDsaTest : CryptoConfigRequiredTest
    {
        protected abstract GostECDsa Create(ECParameters parameters);

        protected void CheckExportParameters(ECParameters parameters)
        {
            ECParameters exportedParameters;
            using (GostECDsa algorithm = Create(parameters))
            {
                exportedParameters = algorithm.ExportParameters(false);

                exportedParameters.Validate();
                AssertEqual(parameters, exportedParameters, false);
                Assert.Null(exportedParameters.D);

                if (parameters.D != null)
                {
                    exportedParameters = algorithm.ExportParameters(true);
                    exportedParameters.Validate();
                    AssertEqual(parameters, exportedParameters, true);
                }
            }
        }

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
