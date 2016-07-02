using System.Collections.Generic;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    public class GostECDsaTests
    {
        #region Test domain parameters as described in GOST 34.10-2012

        private static ECParameters TestDomainParameters256 { get; } = new ECParameters
        {
            Curve = new ECCurve
            {
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

        private static ECParameters TestDomainParameters512 { get; } = new ECParameters
        {
            Curve = new ECCurve
            {
                Prime = "7363be28f5bb6416d84d22ac6f33b8356d54e4807e0458044a70f41a7452d8f15dd1d2b5097cebd4040fb9ffb2142b9280ee2f6b7b260d55c72300fed1ac3145".HexToByteArray(),
                A = "07000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                B = "dc2a304f08a3d0fa9768dd2a0c549ebc74cfe058ca890a482273adb21340836143aca1ec49b688d7fd0094e477f3c58b74eb574ea5cfd829da1611a30608ff1c".HexToByteArray(),
                Order = "dfe6e687f1aa44d695c523beed256ed8f123c4ec5e5c9019c7ba1dcb7e2d2fa85dd1d2b5097cebd4040fb9ffb2142b9280ee2f6b7b260d55c72300fed1ac3145".HexToByteArray(),
                Cofactor = "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                G = new ECPoint
                {
                    X = "9a8a2420b1f130b5b433ac7f9749c88be204e8eea70ab6c68d83cd62126160fd62d78ca69310f925c87c05d7b3b313526c7afdbb6ebf96f330ee7245c69cd124".HexToByteArray(),
                    Y = "1e37dd1acb92bb6d0b64241bb9181adc434eeee15133ebf76b49f1776d15ab832c9bf359c24724f3c3f2e5911e06bfcfddac57c81306020d6eced23ba412b32b".HexToByteArray(),
                }
            },
            Q = new ECPoint
            {
                X = "e1ef30d52c6133ddd99d1d5c41455cf7df4d8b4c925bbc69af1433d15658515add2146850c325c5b81c133be655aa8c4d440e7b98a8d59487b0c7696bcc55d11".HexToByteArray(),
                Y = "ecbe7736a9ec357ff2fd39931f4e114cb8cda359270ac7f0e7ff43d9419419ea61fd2ab77f5d9f63523d3b50a04f63e2a0cf51b7c13adc21560f0bd40cc9c737".HexToByteArray(),
            },
            D = "d48da11f826729c6dfaa18fd7b6b63a214277e82d2da223356a000223b12e87220108b508e50e70e70694651e8a09130c9d75677d43609a41b24aead8a04a60b".HexToByteArray(),
        };

        #endregion

        protected GostECDsa Create(ECParameters parameters)
            => new GostECDsaManaged(parameters);

        protected bool VerifyHash(ECParameters parameters, byte[] hash, byte[] signature)
        {
            using (GostECDsa algorithm = Create(parameters))
                return algorithm.VerifyHash(hash, signature);
        }

        protected bool VerifyHash(ECParameters parameters, string hashHex, string signatureHex)
            => VerifyHash(parameters, hashHex.HexToByteArray(), signatureHex.HexToByteArray());

        [Theory(DisplayName = nameof(GostECDsaTests) + "_" + nameof(SignAndVerifyHash))]
        [MemberData(nameof(TestDomainParameters))]
        public void SignAndVerifyHash(ECParameters parameters)
        {
            byte[] hash, signature;
            using (GostECDsa algorithm = Create(parameters))
            {
                hash = GenerateRandomBytes(algorithm.KeySize / 8);
                signature = algorithm.SignHash(hash);
            }

            Assert.True(VerifyHash(parameters, hash, signature));
        }

        [Theory(DisplayName = nameof(GostECDsaTests) + "_" + nameof(VerifyHashTestCases))]
        [MemberData(nameof(TestCases))]
        public void VerifyHashTestCases(ECParameters parameters, string hashHex, string signatureHex)
            => Assert.True(VerifyHash(parameters, hashHex, signatureHex));

        public static IEnumerable<object[]> TestDomainParameters()
        {
            return new[]
            {
                new object[]  { TestDomainParameters256, },
                new object[]  { TestDomainParameters512, },
            };
        }

        // Test cases as described in GOST 34.10-2012
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
                new object[]
                {
                    TestDomainParameters512,
                    "8c5b0772297d77c64f0c561ddbde7a405a5d7c646c97394341f4936553ee847191c5b03570141da733c570c1f9b6091b53ab8d4d7c4a4f5c61e0c9accff35437", // hash
                    "4a5b3ee7bd53982ab99c91561feb6e6a40ce707fdf80605262f3c4e888e23c82f52fd533e9fb0b1c08bcad8a77565f32b6262d36a9e785658efe6f6994b38110" + // s
                    "36ae73e14493e117335c9ccdcb3bc96002859906c997c19e1c0fb28684559254d3acfca8ee783c64c2dce02ec8a312e59e683c1e5e79dd231a0981a060fa862f" // r
                },
            };
        }
    }
}