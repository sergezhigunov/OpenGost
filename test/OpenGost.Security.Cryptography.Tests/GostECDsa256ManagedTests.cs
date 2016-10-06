using System.Collections.Generic;
#if NETCOREAPP1_0
using System.Security.Cryptography;
#endif
using Xunit;

namespace OpenGost.Security.Cryptography
{
#if NET45
    using static CryptoConstants; 
#endif

    public class GostECDsa256ManagedTests : GostECDsaTest<GostECDsa256Managed>
    {
        #region 256-bit test domain parameters as described in GOST 34.10-2012

        private static ECParameters TestDomainParameters256 { get; } = new ECParameters
        {
            Curve = ECCurveOidMap.GetExplicitCurveByOid("1.2.643.7.1.2.1.1.0"),
            Q = new ECPoint
            {
                X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
                Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
            },
            D = "283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a".HexToByteArray(),
        };

        #endregion

        [Theory(DisplayName = nameof(SignAndVerifyHash))]
        [MemberData(nameof(TestDomainParameters))]
        public new void SignAndVerifyHash(ECParameters parameters)
            => base.SignAndVerifyHash(parameters);

        [Theory(DisplayName = nameof(VerifyHashTestCases))]
        [MemberData(nameof(TestCases))]
        public void VerifyHashTestCases(ECParameters parameters, string hashHex, string signatureHex)
            => Assert.True(VerifyHash(parameters, hashHex, signatureHex));

        [Theory(DisplayName = nameof(ExportParametersTest))]
        [MemberData(nameof(TestDomainParameters))]
        public void ExportParametersTest(ECParameters parameters)
            => CheckExportParameters(parameters);

#if NET45
        [Theory(DisplayName = nameof(CheckWriteAndReadXmlString))]
        [MemberData(nameof(TestDomainParameters))]
        public void CheckWriteAndReadXmlString(ECParameters parameters)
            => WriteAndReadXmlString(parameters);

        [Fact(DisplayName = nameof(CheckKeyExchangeAlgorithmProperty))]
        public new void CheckKeyExchangeAlgorithmProperty()
            => base.CheckKeyExchangeAlgorithmProperty();

        [Fact(DisplayName = nameof(CheckSignatureAlgorithmProperty))]
        public void CheckSignatureAlgorithmProperty()
            => CheckSignatureAlgorithmProperty(GostECDsa256AlgorithmName); 
#endif

        [Fact(DisplayName = nameof(CheckKeyGeneration))]
        public void CheckKeyGeneration()
            => CheckKeyGeneration(TestDomainParameters256.Curve);

        [Fact(DisplayName = nameof(CheckDefaultKeyGeneration))]
        public new void CheckDefaultKeyGeneration()
           => base.CheckDefaultKeyGeneration();

        [Theory(DisplayName = nameof(SignHashNullHashThrowsArgumentNullException))]
        [MemberData(nameof(RealImplementations))]
        protected new void SignHashNullHashThrowsArgumentNullException(GostECDsa256Managed algorithm)
           => base.SignHashNullHashThrowsArgumentNullException(algorithm);

        [Theory(DisplayName = nameof(VerifyHashNullHashThrowsArgumentNullException))]
        [MemberData(nameof(RealImplementations))]
        protected new void VerifyHashNullHashThrowsArgumentNullException(GostECDsa256Managed algorithm)
            => base.VerifyHashNullHashThrowsArgumentNullException(algorithm);

        [Theory(DisplayName = nameof(VerifyHashNullSignatureThrowsArgumentNullException))]
        [MemberData(nameof(RealImplementations))]
        protected new void VerifyHashNullSignatureThrowsArgumentNullException(GostECDsa256Managed algorithm)
            => base.VerifyHashNullSignatureThrowsArgumentNullException(algorithm);

        public static IEnumerable<object[]> TestDomainParameters()
        {
            return new[]
            {
                new object[]  { TestDomainParameters256, },
            };
        }

        // 256-bit test cases as described in GOST 34.10-2012
        public static IEnumerable<object[]> TestCases()
        {
            return new[]
            {
                new object[]
                {
                    TestDomainParameters256,
                    "e53e042b67e6ec678e2e02b12a0352ce1fc6eee0529cc088119ad872b3c1fb2d", // hash
                    "409cbfc5f6148092df31b646f7d3d6bc4902a6985a233c65a14246ba646c4501" + // s
                    "9304dc39fd43d03ab86727a45435057419a4ed6fd59ecd808214abf1d228aa41" // r
                },
            };
        }

        public static IEnumerable<object[]> RealImplementations()
        {
            yield return new[] { new GostECDsa256Managed() };
        }
    }
}