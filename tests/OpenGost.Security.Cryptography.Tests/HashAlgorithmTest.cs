using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public abstract class HashAlgorithmTest<T>
        where T : HashAlgorithm, new()
    {
        protected void Verify(string input, Encoding inputEncoding, string expectedHexadecimal)
            => Verify(inputEncoding.GetBytes(input), expectedHexadecimal);

        protected void Verify(byte[] input, string expectedHexadecimal)
        {
            var expected = expectedHexadecimal.HexToByteArray();
            byte[] actual;

            using (var hash = new T())
            {
                Assert.True(hash.HashSize > 0);
                actual = hash.ComputeHash(input, 0, input.Length);
            }

            Assert.Equal(expected, actual);
        }
    }
}
