namespace OpenGost.Security.Cryptography.Tests;

public class ReusabilityFacts
{
    [Theory]
    [MemberData(nameof(ReusabilityHashAlgorithms))]
    public void ReuseHashAlgorithm(Func<HashAlgorithm> hashAlgorithmFactory)
    {
        using var hashAlgorithm = hashAlgorithmFactory.Invoke();
        byte[] input = [0x08, 0x06, 0x07, 0x05, 0x03, 0x00, 0x09];

        var hash1 = hashAlgorithm.ComputeHash(input);
        var hash2 = hashAlgorithm.ComputeHash(input);

        Assert.Equal(hash1, hash2);
    }

    public static TheoryData<Func<HashAlgorithm>> ReusabilityHashAlgorithms()
        => new()
        {
            { () => new Streebog256Managed() },
            { () => new Streebog512Managed() },
            { () => new CMACGrasshopper() },
            { () => new CMACMagma() },
        };
}
