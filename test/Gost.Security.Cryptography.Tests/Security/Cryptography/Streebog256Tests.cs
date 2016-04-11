using Xunit;

namespace Gost.Security.Cryptography
{
    using static TestsUtils;

    public class Streebog256Tests
    {
        [Theory(DisplayName = nameof(Streebog256Tests) + "_" + nameof(ComputeHashTest))]
        [InlineData(
           "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130",
           "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")]
        [InlineData(
           "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1",
           "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")]
        [InlineData(
            "",
            "bbe19c8d2025d99f943a932a0b365a822aa36a4c479d22cc02c8973e219a533f")]
        public void ComputeHashTest(string message, string expectedHashCode)
        {
            byte[]
                messageBytes = FromHexadecimalBigEndian(message),
                hashCode;

            using (var hashAlgorithm = new Streebog256Managed())
                hashCode = hashAlgorithm.ComputeHash(messageBytes);

            // Big-endian byte order comparation
            Assert.Equal(expectedHashCode, hashCode.ToHexadecimalStringBigEndian());
        }
    }
}
