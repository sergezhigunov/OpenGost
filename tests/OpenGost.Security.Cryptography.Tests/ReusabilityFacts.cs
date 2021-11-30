using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography;

public class ReusabilityFacts : CryptoConfigRequiredTest
{
    [Theory]
    [MemberData(nameof(ReusabilityHashAlgorithms))]
    public void ReuseHashAlgorithm(Func<HashAlgorithm> hashAlgorithmFactory)
    {
        using var hashAlgorithm = hashAlgorithmFactory.Invoke();
        byte[] input = { 0x08, 0x06, 0x07, 0x05, 0x03, 0x00, 0x09, };

        var hash1 = hashAlgorithm.ComputeHash(input);
        var hash2 = hashAlgorithm.ComputeHash(input);

        Assert.Equal(hash1, hash2);
    }

    public static IEnumerable<object[]> ReusabilityHashAlgorithms()
    {
        return new[]
        {
            new Func<HashAlgorithm>[] { () => new Streebog256Managed(), },
            new Func<HashAlgorithm>[] { () => new Streebog512Managed(), },
            new Func<HashAlgorithm>[] { () => new CMACGrasshopper(), },
            new Func<HashAlgorithm>[] { () => new CMACMagma(), },
        };
    }
}
