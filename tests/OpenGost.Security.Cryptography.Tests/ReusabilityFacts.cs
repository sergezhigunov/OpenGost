namespace OpenGost.Security.Cryptography.Tests;

public class ReusabilityFacts
{
    [Theory]
    [InlineData(typeof(CMACGrasshopper))]
    [InlineData(typeof(CMACMagma))]
    [InlineData(typeof(HMACStreebog256))]
    [InlineData(typeof(HMACStreebog512))]
    [InlineData(typeof(Streebog256Managed))]
    [InlineData(typeof(Streebog512Managed))]
    public void ReuseHashAlgorithm(Type hashAlgorithmType)
    {
        using var hashAlgorithm = (HashAlgorithm)Activator.CreateInstance(hashAlgorithmType)!;
        byte[] input = [0x08, 0x06, 0x07, 0x05, 0x03, 0x00, 0x09];

        var hash1 = hashAlgorithm.ComputeHash(input);
        var hash2 = hashAlgorithm.ComputeHash(input);

        Assert.Equal(hash1, hash2);
        Assert.NotSame(hash1, hash2);
    }
}
