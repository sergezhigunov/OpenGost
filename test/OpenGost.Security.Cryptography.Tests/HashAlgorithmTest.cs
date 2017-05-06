using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public abstract class HashAlgorithmTest<T>
        where T : HashAlgorithm, new()
    {
        protected static Encoding CurrentEncoding { get; } =
#if NET45
            Encoding.GetEncoding(1251);
#elif NETCOREAPP1_0
            CodePagesEncodingProvider.Instance.GetEncoding(1251);
#endif

        protected void Verify(string input, Encoding inputEncoding, string expectedHexadecimal)
            => Verify(inputEncoding.GetBytes(input), expectedHexadecimal);

        protected void Verify(byte[] input, string expectedHexadecimal)
        {
            byte[] expected = expectedHexadecimal.HexToByteArray();
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
