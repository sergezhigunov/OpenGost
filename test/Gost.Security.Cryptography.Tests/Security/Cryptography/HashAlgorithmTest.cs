using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Gost.Security.Cryptography
{
    public abstract class HashAlgorithmTest : CryptoConfigRequiredTest
    {
        protected abstract HashAlgorithm Create();

        protected void Verify(string input, Encoding inputEncoding, string expectedHexadecimal)
        {
            Verify(inputEncoding.GetBytes(input), expectedHexadecimal);
        }

        protected void Verify(Stream input, string expectedHexadecimal)
        {
            byte[] expected = expectedHexadecimal.HexToByteArray();
            byte[] actual;

            using (HashAlgorithm hash = Create())
            {
                Assert.True(hash.HashSize > 0);
                actual = hash.ComputeHash(input);
            }

            Assert.Equal(expected, actual);
        }

        protected void Verify(byte[] input, string expectedHexadecimal)
        {
            byte[] expected = expectedHexadecimal.HexToByteArray();
            byte[] actual;

            using (HashAlgorithm hash = Create())
            {
                Assert.True(hash.HashSize > 0);
                actual = hash.ComputeHash(input, 0, input.Length);
            }

            Assert.Equal(expected, actual);
        }
    }
}
