using System;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public abstract class CmacTest<T> : CryptoConfigRequiredTest
        where T : CMAC, new()
    {
        protected void VerifyCmac(string dataHex, string keyHex, string digestHex)
        {
            var digestBytes = digestHex.HexToByteArray();
            byte[] computedDigest;

            using (var cmac = new T())
            {
                Assert.True(cmac.HashSize > 0);

                var key = keyHex.HexToByteArray();
                cmac.Key = key;

                // make sure the getter returns different objects each time
                Assert.NotSame(key, cmac.Key);
                Assert.NotSame(cmac.Key, cmac.Key);

                // make sure the setter didn't cache the exact object we passed in
                key[0] = (byte)(key[0] + 1);
                Assert.NotEqual<byte>(key, cmac.Key);

                computedDigest = cmac.ComputeHash(dataHex.HexToByteArray());
            }

            Assert.Equal(digestBytes, computedDigest);
        }

        [Fact]
        public void Key_Throws_IfValueIsNull()
        {
            byte[] value = null!;
            using var cmac = new T();

            Assert.Throws<ArgumentNullException>(nameof(value), () => cmac.Key = value);
        }
    }
}
