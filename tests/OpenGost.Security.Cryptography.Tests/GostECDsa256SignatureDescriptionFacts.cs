using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsa256SignatureDescriptionFacts : SignatureDescriptionTest<GostECDsa256SignatureDescription>
{
    [Fact]
    public void CreateDigest_CreatesValidHashAlgorithm()
    {
        using var digest = CreateDigest();

        Assert.NotNull(digest);
        Assert.True(digest is Streebog256);
    }
}
