using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    public abstract class CmacTest
    {
        protected abstract CMAC Create();

        protected void VerifyCmac(string dataHex, string keyHex, string digestHex)
        {
            byte[] digestBytes = digestHex.HexToByteArray();
            byte[] computedDigest;

            using (CMAC cmac = Create())
            {
                Assert.True(cmac.HashSize > 0);

                byte[] key = keyHex.HexToByteArray();
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
    }
}
