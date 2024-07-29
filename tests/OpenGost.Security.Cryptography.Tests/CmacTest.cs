using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography.Tests;

public abstract class CmacTest<T>
    where T : CMAC, new()
{
    protected virtual int KeySize => 256;
    public abstract int HashSize { get; }

    [Fact]
    public void Constructor_WithoutParameters_InitializesInstance()
    {
        using var cmac = new T();

        Assert.Equal(HashSize, cmac.HashSize);
        var key = cmac.Key;
        Assert.Contains(key, x => x != 0);
        Assert.Equal(KeySize / 8, key.Length);

        // make sure the getter returns different objects each time
        Assert.NotSame(key, cmac.Key);
        Assert.NotSame(cmac.Key, cmac.Key);

        // make sure the setter didn't cache the exact object we passed in
        key[0] = (byte)(key[0] + 1);
        Assert.NotEqual<byte>(key, cmac.Key);
    }

    public virtual void VerifyCmac(string dataHex, string keyHex, string digestHex)
    {
        var digestBytes = Convert.FromHexString(digestHex);
        byte[] computedDigest;

        using (var cmac = new T())
        {
            Assert.True(cmac.HashSize > 0);

            var key = Convert.FromHexString(keyHex);
            cmac.Key = key;

            // make sure the getter returns different objects each time
            Assert.NotSame(key, cmac.Key);
            Assert.NotSame(cmac.Key, cmac.Key);

            // make sure the setter didn't cache the exact object we passed in
            key[0] = (byte)(key[0] + 1);
            Assert.NotEqual<byte>(key, cmac.Key);

            computedDigest = cmac.ComputeHash(Convert.FromHexString(dataHex));
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

    [Fact]
    public void Key_WhenSetsAfterStart_ThrowsCryptographicException()
    {
        using var cmac = new T();
        var value = cmac.Key;
        var input = CryptoUtils.GenerateRandomBytes(1);
        cmac.TransformBlock(input, 0, input.Length, input, 0);

        Assert.Throws<CryptographicException>(() => cmac.Key = value);
    }
}
