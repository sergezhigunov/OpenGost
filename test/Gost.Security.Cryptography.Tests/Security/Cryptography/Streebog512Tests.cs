using Xunit;

namespace Gost.Security.Cryptography
{
    using static TestsUtils;

    public class Streebog512Tests
    {
        [Theory(DisplayName = nameof(Streebog512Tests) + "_" + nameof(ComputeHashTest))]
        [InlineData(
            "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130",
            "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")]
        [InlineData(
            "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1",
            "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e")]
        [InlineData(
            "",
            "8a1a1c4cbf909f8ecb81cd1b5c713abad26a4cac2a5fda3ce86e352855712f36a7f0be98eb6cf51553b507b73a87e97946aebc29859255049f86aa09a25d948e")]
        public void ComputeHashTest(string message, string expectedHashCode)
        {
            byte[]
                messageBytes = FromHexadecimalBigEndian(message),
                hashCode;

            using (var hashAlgorithm = new Streebog512Managed())
                hashCode = hashAlgorithm.ComputeHash(messageBytes);

            // Big-endian byte order comparation
            Assert.Equal(expectedHashCode, hashCode.ToHexadecimalStringBigEndian());
        }
    }
}
