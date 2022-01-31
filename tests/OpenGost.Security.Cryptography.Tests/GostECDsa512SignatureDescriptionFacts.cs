using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsa512SignatureDescriptionFacts : SignatureDescriptionTest<GostECDsa512SignatureDescription>
{
    [Fact]
    public void CreateDigest_CreatesValidHashAlgorithm()
    {
        using var digest = CreateDigest();

        Assert.NotNull(digest);
        Assert.True(digest is Streebog512);
    }
}
