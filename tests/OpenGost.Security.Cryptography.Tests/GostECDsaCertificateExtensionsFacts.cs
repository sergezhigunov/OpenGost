using System.Security.Cryptography.X509Certificates;

namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsaCertificateExtensionsFacts
{
    [Fact]
    public void GetGostECDsaPublicKey_Throws_IfCertificateParameterIsNull()
    {
        var certificate = default(X509Certificate2)!;

        Assert.Throws<ArgumentNullException>(nameof(certificate),
            () => certificate.GetGostECDsaPublicKey());
    }

    [Fact]
    public void GetGostECDsaPublicKey_IfRSACertificate_ReturnsNull()
    {
        using var certificate = GetCertificate("rfc5280_cert1");

        var publicKey = certificate.GetGostECDsaPublicKey();

        Assert.Null(publicKey);
    }

    [Theory]
    [MemberData(nameof(TestCases))]
    public void GetGostECDsaPublicKey_ReturnsPublicKey(
        string certificateName,
        string curveOid,
        string publicKeyXHexData,
        string publicKeyYHexData,
        string privateKeyHexData)
    {
        using var certificate = GetCertificate(certificateName);
        var point = new ECPoint
        {
            X = HexUtils.HexToByteArray(publicKeyXHexData),
            Y = HexUtils.HexToByteArray(publicKeyYHexData),
        };
        _ = HexUtils.HexToByteArray(privateKeyHexData);

        using var publicKey = certificate.GetGostECDsaPublicKey();

        Assert.NotNull(publicKey);
        var parameters = publicKey!.ExportParameters(true);
        Assert.True(parameters.Curve.IsNamed);
        Assert.Equal(curveOid, parameters.Curve.Oid.Value);
        Assert.Equal(point.X, parameters.Q.X);
        Assert.Equal(point.Y, parameters.Q.Y);
        Assert.Null(parameters.D);
    }

    private static X509Certificate2 GetCertificate(string certificateName)
    {
        return new X509Certificate2(
            ResourceUtils.GetBinaryResource(
                $"OpenGost.Security.Cryptography.Tests.Resources.{certificateName}.cer"));
    }

    public static TheoryData<string, string, string, string, string> TestCases
        => new()
        {
            // 256-bit example
            {
                // Certificate name
                "GostECDsa256",
                // Curve OID
                "1.2.643.2.2.36.0",
                // X
                "badfd0c35314abd28faa47470b6c401772bb4ee8077e8f67e76e43dace661597",
                // Y
                "43e69c1ff74fe2e2f1749859abf677d1c0c60fe28d0f83598e9f9465697358ad",
                // D
                "249939faa839edc3f2aafe0f643de4463c924abbeac6a73230dd5c3e621dcfbf"
            },
            // 512-bit example
            {
                // Certificate name
                "GostECDsa512",
                // Curve OID
                "1.2.643.7.1.2.1.2.2",
                // X
                "13190f550a233915118243c304cf617574036a85a12ecb06bc09bc4e9d3bda18" +
                "9a454155d0c24c2f2c500a87b864e78daf384b71a4ab530977c67fce27461307",
                // Y
                "fd0f5b65e01cd9e3bfca1c6bb1085306e7dad45ba8bb6a1efe350e686e9102d5" +
                "14bd1ce1353a694461a5d7e108636bf3cd4b9af63f4e97f800a32fcb34a4087e",
                // D
                "4b07cb6b4e014ea4e67d0c5f17fd33fd488cb4eec876b987e57c0741e6307575" +
                "352446ee5aa02b99679efe8d5280f3b76de6414c7782b42e975fecd4dc1cc03f"
            },
        };

}
