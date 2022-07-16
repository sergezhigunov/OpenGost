using System;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class OpenGostCryptoConfigTests
{
    [Theory]
    [InlineData("1.2.643.7.1.1.2.2", nameof(Streebog256))]
    [InlineData("1.2.643.7.1.1.2.3", nameof(Streebog512))]
    public void CryptoConfig_MapNameToOID_ReturnsMapped(string expected, string name)
    {
        var actual = CryptoConfig.MapNameToOID(name);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(typeof(GostECDsaManaged), nameof(GostECDsa))]
    [InlineData(typeof(GrasshopperManaged), nameof(Grasshopper))]
    [InlineData(typeof(MagmaManaged), nameof(Magma))]
    [InlineData(typeof(Streebog256Managed), nameof(Streebog256))]
    [InlineData(typeof(Streebog512Managed), nameof(Streebog512))]
    [InlineData(typeof(CMACGrasshopper), nameof(CMACGrasshopper))]
    [InlineData(typeof(CMACMagma), nameof(CMACMagma))]
    [InlineData(typeof(HMACStreebog256), nameof(HMACStreebog256))]
    [InlineData(typeof(HMACStreebog512), nameof(HMACStreebog512))]
    [InlineData(typeof(GostECDsa256SignatureDescription), OpenGostSignedXml.XmlDsigGostECDsaStreebog256Url)]
    [InlineData(typeof(GostECDsa512SignatureDescription), OpenGostSignedXml.XmlDsigGostECDsaStreebog512Url)]
    public void CryptoConfig_CreateFromName_ReturnsMapped(Type expectedType, string name)
    {
        var actual = CryptoConfig.CreateFromName(name);

        Assert.NotNull(actual);
        Assert.IsType(expectedType, actual);
    }
}
