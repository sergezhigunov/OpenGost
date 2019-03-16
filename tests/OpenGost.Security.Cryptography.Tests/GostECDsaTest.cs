using System;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    using static CryptoUtils;
    using static ECHelper;

    public abstract class GostECDsaTest<T> : AsymmetricAlgorithmTest<T>
        where T : GostECDsa, new()
    {
        protected T Create(ECParameters parameters)
        {
            var algorithm = new T();
            algorithm.ImportParameters(parameters);
            return algorithm;
        }

        protected void CheckExportParameters(ECParameters parameters)
        {
            ECParameters exportedParameters;
            using (T algorithm = Create(parameters))
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
            using (T algorithm = Create(parameters))
                return algorithm.VerifyHash(hash, signature);
        }

        protected bool VerifyHash(ECParameters parameters, string hashHex, string signatureHex)
            => VerifyHash(parameters, hashHex.HexToByteArray(), signatureHex.HexToByteArray());

        public virtual void SignAndVerifyHash(ECParameters parameters)
        {
            byte[] hash, signature;
            using (T algorithm = Create(parameters))
            {
                hash = GenerateRandomBytes(algorithm.KeySize / 8);
                signature = algorithm.SignHash(hash);
            }

            Assert.True(VerifyHash(parameters, hash, signature));
        }

        protected void WriteAndReadXmlString(ECParameters parameters)
        {
            parameters.Validate();

            string xmlString;
            using (T algorithm = Create(parameters))
                xmlString = algorithm.ToXmlString(false);

            Assert.False(string.IsNullOrEmpty(xmlString));

            ECParameters newParameters;
            using (T algorithm = Create(xmlString))
                newParameters = algorithm.ExportParameters(false);

            AssertEqual(parameters, newParameters, false);
        }

        public virtual void CheckKeyExchangeAlgorithmProperty()
        {
            using (var algorithm = new T())
                Assert.Null(algorithm.KeyExchangeAlgorithm);
        }

        public virtual void CheckSignatureAlgorithmProperty(string expectedSignatureAlgorithm)
        {
            using (var algorithm = new T())
                Assert.Equal(expectedSignatureAlgorithm, algorithm.SignatureAlgorithm);
        }

        public virtual void CheckKeyGeneration(ECParameters curveParameters)
        {
            ECCurve curve = curveParameters.Curve;
            using (var algorithm = new T())
            {
                algorithm.GenerateKey(curve);
                ECParameters parameters = algorithm.ExportParameters(true);
                parameters.Validate();
            }
        }

        public virtual void CheckDefaultKeyGeneration()
        {
            using (var algorithm = new T())
            {
                ECParameters parameters = algorithm.ExportParameters(true);
                parameters.Validate();
            }
        }

        public virtual void SignHashNullHashThrowsArgumentNullException(T algorithm)
            => Assert.Throws<ArgumentNullException>("hash", () => algorithm.SignHash(null));

        public virtual void VerifyHashNullHashThrowsArgumentNullException(T algorithm)
            => Assert.Throws<ArgumentNullException>("hash", () => algorithm.VerifyHash(null, null));

        public virtual void VerifyHashNullSignatureThrowsArgumentNullException(T algorithm)
            => Assert.Throws<ArgumentNullException>("signature", () => algorithm.VerifyHash(new byte[0], null));
    }
}
