using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsaManagedFacts
{
    #region Test domain parameters as described in GOST 34.10-2018

    private static ECParameters TestDomainParameters256 { get; } = new ECParameters
    {
        Curve = ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.0"),
        Q = new ECPoint
        {
            X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
            Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
        },
        D = "283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a".HexToByteArray(),
    };

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

    [Fact]
    public void Constructor_SetsValidDefaultKeySize()
    {
        using var algorithm = new GostECDsaManaged();

        Assert.Equal(512, algorithm.KeySize);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(512)]
    public void SignHash_CreatesVerifiableSignature_IfParametersWasNotGenerated(int keySize)
    {
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };
        var hash = CryptoUtils.GenerateRandomBytes(algorithm.KeySize / 8);

        var signature = algorithm.SignHash(hash);

        Assert.True(algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void SignHash_CreatesVerifiableSignature_OnTestDomainParameters(ECParameters parameters)
    {
        using var algorithm = new GostECDsaManaged(parameters);
        var hash = CryptoUtils.GenerateRandomBytes(algorithm.KeySize / 8);

        var signature = algorithm.SignHash(hash);

        Assert.True(algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [InlineData(0, 512)]
    [InlineData(256, 512)]
    [InlineData(511, 512)]
    [InlineData(0, 256)]
    [InlineData(255, 256)]
    [InlineData(257, 256)]
    [InlineData(512, 256)]
    public void SignHash_CryptographicException_IfHashSizeIsInvalid(int hashSize, int keySize)
    {
        var hash = CryptoUtils.GenerateRandomBytes(hashSize);
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };

        Assert.Throws<CryptographicException>(() => algorithm.SignHash(hash));
    }

    [Fact]
    public void SignHash_ThrowsArgumentNullException_IfHashParameterIsNull()
    {
        var hash = default(byte[])!;
        using var algorithm = new GostECDsaManaged();

        Assert.Throws<ArgumentNullException>(nameof(hash),
            () => algorithm.SignHash(hash));
    }

    [Theory]
    [MemberData(nameof(TestCases))]
    public void VerifyHash_WhenSignatureIsValid_ReturnsTrue(
        ECParameters parameters,
        byte[] hash,
        byte[] signature)
    {
        using var algorithm = new GostECDsaManaged(parameters);

        Assert.True(algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [InlineData(256)]
    public void VerifyHash_ReturnsFalse_IfParametersWasNotGenereated(int keySize)
    {
        var hash = CryptoUtils.GenerateRandomBytes(keySize / 8);
        var signature = CryptoUtils.GenerateRandomBytes(keySize / 4);
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };

        Assert.False(algorithm.VerifyHash(hash, signature));
    }

    [Fact]
    public void VerifyHash_ThrowsArgumentNullException_IfHashParameterIsNull()
    {
        var hash = default(byte[])!;
        var signature = CryptoUtils.GenerateRandomBytes(128);
        using var algorithm = new GostECDsaManaged();

        Assert.Throws<ArgumentNullException>(nameof(hash),
            () => algorithm.VerifyHash(hash, signature));
    }

    [Fact]
    public void VerifyHash_ThrowsArgumentNullException_IfSignatureParameterIsNull()
    {
        var hash = CryptoUtils.GenerateRandomBytes(64);
        var signature = default(byte[])!;
        using var algorithm = new GostECDsaManaged();

        Assert.Throws<ArgumentNullException>(nameof(signature),
            () => algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [InlineData(0, 512)]
    [InlineData(32, 512)]
    [InlineData(63, 512)]
    [InlineData(0, 256)]
    [InlineData(31, 256)]
    [InlineData(33, 256)]
    [InlineData(64, 256)]
    public void VerifyHash_CryptographicException_IfHashSizeIsInvalid(int hashSize, int keySize)
    {
        var hash = CryptoUtils.GenerateRandomBytes(hashSize);
        var signature = CryptoUtils.GenerateRandomBytes(keySize / 4);
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };

        Assert.Throws<CryptographicException>(
            () => algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [InlineData(0, 512)]
    [InlineData(64, 512)]
    [InlineData(127, 512)]
    [InlineData(0, 256)]
    [InlineData(63, 256)]
    [InlineData(65, 256)]
    [InlineData(128, 256)]
    public void VerifyHash_CryptographicException_IfSignatureSizeIsInvalid(int signatureSize, int keySize)
    {
        var hash = CryptoUtils.GenerateRandomBytes(keySize / 8);
        var signature = CryptoUtils.GenerateRandomBytes(signatureSize);
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };

        Assert.Throws<CryptographicException>(
            () => algorithm.VerifyHash(hash, signature));
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void ExportParameters_ExportsValidParametersWithPrivateKey_IfHasPrivateKeyAndIncludePrivateParametersIsTrue(
        ECParameters parameters)
    {
        using var algorithm = new GostECDsaManaged(parameters);

        var result = algorithm.ExportParameters(true);

        result.Validate();
        ECHelper.AssertEqual(parameters.Curve, result.Curve);
        ECHelper.AssertEqual(parameters.Q, result.Q);
        Assert.Equal(parameters.D, result.D);
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void ExportParameters_ExportsValidPublicOnlyParameters_IfHasPrivateKeyAndIncludePrivateParametersIsFalse(
        ECParameters parameters)
    {
        using var algorithm = new GostECDsaManaged(parameters);

        var result = algorithm.ExportParameters(false);

        result.Validate();
        ECHelper.AssertEqual(parameters.Curve, result.Curve);
        ECHelper.AssertEqual(parameters.Q, result.Q);
        Assert.Null(result.D);
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void ExportParameters_ExportsValidPublicOnlyParameters_IfHasNotPrivateKeyAndIncludePrivateParametersIsTrue(
        ECParameters parameters)
    {
        parameters.D = null;
        using var algorithm = new GostECDsaManaged(parameters);

        var result = algorithm.ExportParameters(true);

        result.Validate();
        ECHelper.AssertEqual(parameters.Curve, result.Curve);
        ECHelper.AssertEqual(parameters.Q, result.Q);
        Assert.Null(result.D);
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void ExportParameters_ExportsValidPublicOnlyParameters_IfHasNotPrivateKeyAndIncludePrivateParametersIsFalse(
        ECParameters parameters)
    {
        parameters.D = null;
        using var algorithm = new GostECDsaManaged(parameters);

        var result = algorithm.ExportParameters(false);

        result.Validate();
        ECHelper.AssertEqual(parameters.Curve, result.Curve);
        ECHelper.AssertEqual(parameters.Q, result.Q);
        Assert.Null(result.D);
    }

    [Theory]
    [InlineData(256, "1.2.643.7.1.2.1.1.1")]
    [InlineData(512, "1.2.643.7.1.2.1.2.1")]
    public void ExportParameters_ExportNewGeneratedParametersWithDefaultCurve_IfParametersWasNotSet(
        int keySize,
        string oidValue)
    {
        using var algorithm = new GostECDsaManaged
        {
            KeySize = keySize,
        };

        var parameters = algorithm.ExportParameters(true);
        parameters.Validate();
        Assert.Equal(keySize / 8, parameters.D?.Length);
        var curve = parameters.Curve;
        Assert.True(curve.IsNamed);
        Assert.Equal(oidValue, curve.Oid?.Value);
        // Ensure generated once
        ECHelper.AssertEqual(parameters, algorithm.ExportParameters(true), true);
    }

    [Fact]
    public void KeyExchangeAlgorithm_ReturnsNull_Always()
    {
        using var algorithm = new GostECDsaManaged();

        var result = algorithm.KeyExchangeAlgorithm;

        Assert.Null(result);
    }

    [Fact]
    public void SignatureAlgorithm_ReturnsGostECDsa_Always()
    {
        using var algorithm = new GostECDsaManaged();

        var result = algorithm.SignatureAlgorithm;

        Assert.Equal(nameof(GostECDsa), result);
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void GenerateKey_GeneratesValidParametersWithPrivateKey(ECParameters parameters)
    {
        var curve = parameters.Curve;
        using var algorithm = new GostECDsaManaged();

        algorithm.GenerateKey(curve);

        var result = algorithm.ExportParameters(true);
        result.Validate();
        ECHelper.AssertEqual(parameters.Curve, result.Curve);
        Assert.NotNull(result.D);
    }

    [Theory]
    [MemberData(nameof(TestDomainParameters))]
    public void SignedXml_ComputeSignature_GeneratesValidSignature(ECParameters parameters)
    {
        using var algorithm = new GostECDsaManaged();
        algorithm.ImportParameters(parameters);
        const string methodPrefix = "urn:ietf:params:xml:ns:cpxmlsec:algorithms";
        var signatureMethod = $"{methodPrefix}:gostr34102012-gostr34112012-{algorithm.KeySize}";
        var digestMethod = $"{methodPrefix}:gostr34112012-{algorithm.KeySize}";
        var document = new XmlDocument();
        document.LoadXml("<x/>");
        var root = document.DocumentElement!;
        var signedXml = new SignedXml(root)
        {
            SigningKey = algorithm,
        };
        signedXml.SignedInfo.SignatureMethod = signatureMethod;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        var reference = new Reference
        {
            Uri = string.Empty,
            DigestMethod = digestMethod,
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        signedXml.ComputeSignature();

        var signature = signedXml.Signature;
        Assert.NotNull(signature);
        Assert.Equal(algorithm.KeySize / 4, signature.SignatureValue.Length);
        Assert.Same(signedXml.SignedInfo, signature.SignedInfo);
        Assert.Equal(algorithm.KeySize / 8, reference.DigestValue.Length);
    }

    [Theory]
    [MemberData(nameof(XmlDSigTestCases))]
    public void SignedXml_CheckSignature_ReturnsTrue_IfSignatureValid(ECParameters parameters, string xml)
    {
        using var algorithm = new GostECDsaManaged();
        algorithm.ImportParameters(parameters);
        var document = new XmlDocument();
        document.LoadXml(xml);
        var root = document.DocumentElement!;
        var signedXml = new SignedXml(root);
        var signatureElement =
            (XmlElement)document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]!;
        signedXml.LoadXml(signatureElement);

        var result = signedXml.CheckSignature(algorithm);

        Assert.True(result);
    }

    public static IEnumerable<object[]> TestDomainParameters()
    {
        yield return new object[] { TestDomainParameters256, };
        yield return new object[] { TestDomainParameters512, };
    }

    // Test cases as described in GOST 34.10-2018
    public static IEnumerable<object[]> TestCases()
    {
        yield return new object[]
        {
            TestDomainParameters256,
            // Hash
            HexUtils.HexToByteArray(
                "e53e042b67e6ec678e2e02b12a0352ce1fc6eee0529cc088119ad872b3c1fb2d"),
            // Signature
            HexUtils.HexToByteArray(
                // s
                "409cbfc5f6148092df31b646f7d3d6bc4902a6985a233c65a14246ba646c4501" +
                // r
                "9304dc39fd43d03ab86727a45435057419a4ed6fd59ecd808214abf1d228aa41"),

        };
        yield return new object[]
        {
            TestDomainParameters512,
            // Hash
            HexUtils.HexToByteArray(
                "8c5b0772297d77c64f0c561ddbde7a405a5d7c646c97394341f4936553ee8471" +
                "91c5b03570141da733c570c1f9b6091b53ab8d4d7c4a4f5c61e0c9accff35437"),
            // Signature
            HexUtils.HexToByteArray(
                // s
                "4a5b3ee7bd53982ab99c91561feb6e6a40ce707fdf80605262f3c4e888e23c82" +
                "f52fd533e9fb0b1c08bcad8a77565f32b6262d36a9e785658efe6f6994b38110" +
                // r
                "36ae73e14493e117335c9ccdcb3bc96002859906c997c19e1c0fb28684559254" +
                "d3acfca8ee783c64c2dce02ec8a312e59e683c1e5e79dd231a0981a060fa862f"),
        };
    }

    public static IEnumerable<object[]> XmlDSigTestCases()
    {
        yield return new object[]
        {
            TestDomainParameters256,
            "<x><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorith" +
            "m=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpx" +
            "mlsec:algorithms:gostr34102012-gostr34112012-256\" /><Reference URI=\"\"><Transforms><Transform Algorit" +
            "hm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org" +
            "/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algor" +
            "ithms:gostr34112012-256\" /><DigestValue>JNdsQmFfcmAYYn4g42yK6tw2Gj5Xyxx5ILX3YAlXxBE=</DigestValue></Re" +
            "ference></SignedInfo><SignatureValue>PaW2aNI9T10zcFqL0JBaFIx9fqqk8yyAyh5rsHoOESnoszOqjQ6hVsAmoWsH/TMIOD" +
            "GhHgvMBOJ6U86yq0eKbQ==</SignatureValue></Signature></x>",
        };
        yield return new object[]
        {
            TestDomainParameters512,
            "<x><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorith" +
            "m=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpx" +
            "mlsec:algorithms:gostr34102012-gostr34112012-512\" /><Reference URI=\"\"><Transforms><Transform Algorit" +
            "hm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org" +
            "/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algor" +
            "ithms:gostr34112012-512\" /><DigestValue>SBO2V/znwwwIuO1uz0NpidHq5PWjW3IiAotyRuH2evF/wHWcLyFzZ7zI9KBgF3" +
            "nrPF/NGk7RTdIwDVEbNd6YLg==</DigestValue></Reference></SignedInfo><SignatureValue>jI4sDu+baO3RAN9z1azJl9" +
            "fK7FULxiHqgZf0/+CH27b6kPZ8yYGDGOlpkaHol6lB4DYNLk+qI/qubXkZ2rzQN9jwTX8a3zFvpo4QwtXYavBRuFu8HAntrysUQfhTB" +
            "kB4jZsWI4IbAqGhK5T271xBb+LdWcbg7p+Ehmejr4VUYi0=</SignatureValue></Signature></x>",
        };
    }
}
