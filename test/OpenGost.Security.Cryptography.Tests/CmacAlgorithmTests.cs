using System;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class CmacAlgorithmTests
    {
        [Fact(DisplayName = nameof(SetNullOrEmptyAlgorithmName))]
        public void SetNullOrEmptyAlgorithmName()
        {
            using (CMAC cmac = new TestCMAC())
            {
                Assert.Throws<ArgumentException>(() => cmac.SymmetricAlgorithmName = null);
                Assert.Throws<ArgumentException>(() => cmac.SymmetricAlgorithmName = string.Empty);
                Assert.Equal(null, cmac.SymmetricAlgorithmName);
            }
        }

        [Fact(DisplayName = nameof(SetUnknownAlgorithmName))]
        public void SetUnknownAlgorithmName()
        {
            using (CMAC cmac = new TestCMAC())
            {
                const string UnknownAlgorithmName = "No known algorithm name has spaces, so this better be invalid...";

                Assert.Throws<CryptographicException>(() => cmac.SymmetricAlgorithmName = UnknownAlgorithmName);
                Assert.Equal(null, cmac.SymmetricAlgorithmName);
            }
        }

        private class TestCMAC : CMAC
        { }
    }
}
