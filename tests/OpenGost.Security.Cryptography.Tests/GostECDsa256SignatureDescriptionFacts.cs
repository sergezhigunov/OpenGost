using Xunit;

namespace OpenGost.Security.Cryptography;

public class GostECDsa256SignatureDescriptionFacts : SignatureDescriptionTest<GostECDsa256SignatureDescription>
{
    [Fact]
    public void CreateDigest_CreatesValidHashAlgorithm()
    {
        using var digest = CreateDigest();

        Assert.NotNull(digest);
        Assert.True(digest is Streebog256);
    }

    [Fact]
    public void CreateDeformatter_CreatesValidDeformatter()
    {
        var deformatter = CreateDeformatter(GostECDsa256.Create());

        Assert.NotNull(deformatter);
        Assert.True(deformatter is GostECDsa256SignatureDeformatter);
    }

    [Fact]
    public void CreateFormatter_CreatesValidFormatter()
    {
        var formatter = CreateFormatter(GostECDsa256.Create());

        Assert.NotNull(formatter);
        Assert.True(formatter is GostECDsa256SignatureFormatter);
    }
}
