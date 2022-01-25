using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsa512ManagedFacts : ECDsaTest<GostECDsa512Managed>
{
    #region 512-bit test domain parameters as described in GOST 34.10-2012

    private static ECParameters TestDomainParameters512 { get; } = new ECParameters
    {
        Curve = ECCurve.CreateFromValue("1.2.643.7.1.2.1.2.0"),
        Q = new ECPoint
        {
            X = (
                "e1ef30d52c6133ddd99d1d5c41455cf7df4d8b4c925bbc69af1433d15658515a" +
                "dd2146850c325c5b81c133be655aa8c4d440e7b98a8d59487b0c7696bcc55d11")
                .HexToByteArray(),
            Y = (
                "ecbe7736a9ec357ff2fd39931f4e114cb8cda359270ac7f0e7ff43d9419419ea" +
                "61fd2ab77f5d9f63523d3b50a04f63e2a0cf51b7c13adc21560f0bd40cc9c737")
                .HexToByteArray(),
        },
        D = (
            "d48da11f826729c6dfaa18fd7b6b63a214277e82d2da223356a000223b12e872" +
            "20108b508e50e70e70694651e8a09130c9d75677d43609a41b24aead8a04a60b")
            .HexToByteArray(),
    };

    #endregion

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public override void SignAndVerifyHash(ECParameters parameters)
        => base.SignAndVerifyHash(parameters);

    [Theory]
    [MemberData(nameof(TestCases))]
    public void VerifyHashTestCases(ECParameters parameters, string hashHex, string signatureHex)
        => Assert.True(VerifyHash(parameters, hashHex, signatureHex));

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void ExportParametersTest(ECParameters parameters)
        => CheckExportParameters(parameters);

    [Fact]
    public override void CheckKeyExchangeAlgorithmProperty()
        => base.CheckKeyExchangeAlgorithmProperty();

    [Theory]
    [InlineData(nameof(GostECDsa512))]
    public override void CheckSignatureAlgorithmProperty(string expectedSignatureAlgorithm)
        => base.CheckSignatureAlgorithmProperty(expectedSignatureAlgorithm);

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public override void CheckKeyGeneration(ECParameters parameters)
        => base.CheckKeyGeneration(parameters);

    [Fact]
    public override void CheckDefaultKeyGeneration()
        => base.CheckDefaultKeyGeneration();

    [Theory]
    [MemberData(nameof(RealImplementations))]
    public override void SignHashNullHashThrowsArgumentNullException(GostECDsa512Managed algorithm)
        => base.SignHashNullHashThrowsArgumentNullException(algorithm);

    [Theory]
    [MemberData(nameof(RealImplementations))]
    public override void VerifyHashNullHashThrowsArgumentNullException(GostECDsa512Managed algorithm)
        => base.VerifyHashNullHashThrowsArgumentNullException(algorithm);

    [Theory]
    [MemberData(nameof(RealImplementations))]
    public override void VerifyHashNullSignatureThrowsArgumentNullException(GostECDsa512Managed algorithm)
        => base.VerifyHashNullSignatureThrowsArgumentNullException(algorithm);

    public static IEnumerable<object[]> TestDomainParameters()
    {
        return new[]
        {
                new object[]  { TestDomainParameters512, },
            };
    }

    // 512-bit test cases as described in GOST 34.10-2012
    public static IEnumerable<object[]> TestCases()
    {
        return new[]
        {
            new object[]
            {
                TestDomainParameters512,
                // hash
                "8c5b0772297d77c64f0c561ddbde7a405a5d7c646c97394341f4936553ee8471" +
                "91c5b03570141da733c570c1f9b6091b53ab8d4d7c4a4f5c61e0c9accff35437",
                // s
                "4a5b3ee7bd53982ab99c91561feb6e6a40ce707fdf80605262f3c4e888e23c82" +
                "f52fd533e9fb0b1c08bcad8a77565f32b6262d36a9e785658efe6f6994b38110" +
                // r
                "36ae73e14493e117335c9ccdcb3bc96002859906c997c19e1c0fb28684559254" +
                "d3acfca8ee783c64c2dce02ec8a312e59e683c1e5e79dd231a0981a060fa862f"
            },
        };
    }

    public static IEnumerable<object[]> RealImplementations()
    {
        yield return new[] { new GostECDsa512Managed() };
    }
}
