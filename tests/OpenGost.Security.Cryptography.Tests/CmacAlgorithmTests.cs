using System;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class CmacAlgorithmTests
    {
        [Fact]
        public void SetNullOrEmptyAlgorithmName()
        {
            using CMAC cmac = new TestCMAC();

            Assert.Throws<ArgumentException>(() => cmac.SymmetricAlgorithmName = null);
            Assert.Throws<ArgumentException>(() => cmac.SymmetricAlgorithmName = string.Empty);
            Assert.Null(cmac.SymmetricAlgorithmName);
        }

        [Fact]
        public void SetUnknownAlgorithmName()
        {
            using CMAC cmac = new TestCMAC();
            const string unknownAlgorithmName = "No known algorithm name has spaces, so this better be invalid...";

            Assert.Throws<CryptographicException>(() => cmac.SymmetricAlgorithmName = unknownAlgorithmName);
            Assert.Null(cmac.SymmetricAlgorithmName);
        }

        private class TestCMAC : CMAC
        { }
    }
}
