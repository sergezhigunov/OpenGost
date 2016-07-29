using System;
using System.Collections.Generic;
using Xunit;

namespace Gost.Security.Cryptography
{
    public class GostECDsa256Tests : GostECDsaTest<GostECDsa256>
    {
        #region 256-bit test domain parameters as described in GOST 34.10-2012

        private static ECParameters TestDomainParameters256 { get; } = new ECParameters
        {
            Curve = new ECCurve
            {
                CurveType = ECCurveType.PrimeShortWeierstrass,
                Prime = "3104000000000000000000000000000000000000000000000000000000000080".HexToByteArray(),
                A = "0700000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                B = "7e3be2dae90c4c512afc72346a6e3f5640efaffb22e0b839e78c93aa98f4bf5f".HexToByteArray(),
                Order = "b3f5cc3a19fc9cc554619792188afe5001000000000000000000000000000080".HexToByteArray(),
                Cofactor = "0100000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                G = new ECPoint
                {
                    X = "0200000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                    Y = "c88f7eeabcab962b1267a29c0a7fc9859cd1160e031663bdd44751e6a0a8e208".HexToByteArray(),
                }
            },
            Q = new ECPoint
            {
                X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
                Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
            },
            D = "283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a".HexToByteArray(),
        };

        #endregion

        protected override GostECDsa256 Create() => GostECDsa256.Create();

        [Theory(DisplayName = nameof(GostECDsa256Tests) + "_" + nameof(SignAndVerifyHash))]
        [MemberData(nameof(TestDomainParameters))]
        public new void SignAndVerifyHash(ECParameters parameters)
            => base.SignAndVerifyHash(parameters);

        [Theory(DisplayName = nameof(GostECDsa256Tests) + "_" + nameof(VerifyHashTestCases))]
        [MemberData(nameof(TestCases))]
        public void VerifyHashTestCases(ECParameters parameters, string hashHex, string signatureHex)
            => Assert.True(VerifyHash(parameters, hashHex, signatureHex));

        [Theory(DisplayName = nameof(GostECDsa256Tests) + "_" + nameof(ExportParametersTest))]
        [MemberData(nameof(TestDomainParameters))]
        public void ExportParametersTest(ECParameters parameters)
            => CheckExportParameters(parameters);

        [Theory(DisplayName = nameof(GostECDsa256Tests) + "_" + nameof(CheckWriteAndReadXmlString))]
        [MemberData(nameof(TestDomainParameters))]
        public void CheckWriteAndReadXmlString(ECParameters parameters)
            => WriteAndReadXmlString(parameters);

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
    }
}