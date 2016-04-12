using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public class ReusabilityTests
    {
        [Theory(DisplayName = nameof(ReusabilityTests) + "_" + nameof(ReuseHashAlgorithm))]
        [MemberData(nameof(ReusabilityHashAlgorithms))]
        public void ReuseHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            using (hashAlgorithm)
            {
                byte[] input = { 0x08, 0x06, 0x07, 0x05, 0x03, 0x00, 0x09, };
                byte[] hash1 = hashAlgorithm.ComputeHash(input);
                byte[] hash2 = hashAlgorithm.ComputeHash(input);

                Assert.Equal(hash1, hash2);
            }
        }

        public static IEnumerable<object[]> ReusabilityHashAlgorithms()
        {
            return new[]
            {
                new object[] { Streebog512.Create(), },
                new object[] { Streebog256.Create(), },
                new object[] { new CMACGrasshopper(), },
                new object[] { new CMACMagma(), },
            };
        }
    }
}
