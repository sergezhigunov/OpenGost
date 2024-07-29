namespace OpenGost.Security.Cryptography.Tests;

public abstract class HmacTest<T>
    where T : HMAC, new()
{
    protected virtual int BlockSize => 64;

    protected abstract HashAlgorithm CreateHashAlgorithm();

    protected abstract T CreateHMAC(byte[] key);

    [Fact]
    public void Constructor_WithoutParameters_InitializesInstance()
    {
        var hmac = new T();

        var key = hmac.Key;
        Assert.Contains(key, x => x != 0);
        Assert.Equal(BlockSize, key.Length);

        // make sure the getter returns different objects each time
        Assert.NotSame(key, hmac.Key);
        Assert.NotSame(hmac.Key, hmac.Key);

        // make sure the setter didn't cache the exact object we passed in
        key[0] = (byte)(key[0] + 1);
        Assert.NotEqual<byte>(key, hmac.Key);
    }

    [Fact]
    public void Constructor_WhenKeyIsNull_ThrowsArgumentNullException()
    {
        var key = default(byte[])!;

        Assert.Throws<ArgumentNullException>(nameof(key), () => CreateHMAC(key));
    }

    [Fact]
    public void Key_WhenSetsNull_ThrowsArgumentNullException()
    {
        using var hmac = new T();
        var value = default(byte[])!;

        Assert.Throws<ArgumentNullException>(nameof(value), () => hmac.Key = value);
    }

    [Fact]
    public void Key_WhenSetsAfterStart_ThrowsCryptographicException()
    {
        using var hmac = new T();
        var value = hmac.Key;
        var input = CryptoUtils.GenerateRandomBytes(1);
        hmac.TransformBlock(input, 0, input.Length, input, 0);

        Assert.Throws<CryptographicException>(() => hmac.Key = value);
    }

    public virtual void VerifyHmac(string dataHex, string keyHex, string digestHex)
    {
        var digestBytes = Convert.FromHexString(digestHex);
        byte[] computedDigest;

        using (var hmac = new T())
        {
            Assert.True(hmac.HashSize > 0);

            var key = Convert.FromHexString(keyHex);
            hmac.Key = key;

            // make sure the getter returns different objects each time
            Assert.NotSame(key, hmac.Key);
            Assert.NotSame(hmac.Key, hmac.Key);

            // make sure the setter didn't cache the exact object we passed in
            key[0] = (byte)(key[0] + 1);
            Assert.NotEqual<byte>(key, hmac.Key);

            computedDigest = hmac.ComputeHash(Convert.FromHexString(dataHex));
        }

        Assert.Equal(digestBytes, computedDigest);
    }

    [Fact]
    public void VerifyHmacRfc2104()
    {
        // Ensure that keys shorter than the threshold don't get altered.
        using (var hmac = new T())
        {
            var key = new byte[BlockSize];
            hmac.Key = key;
            var retrievedKey = hmac.Key;
            Assert.Equal<byte>(key, retrievedKey);
        }

        // Ensure that keys longer than the threshold are adjusted via Rfc2104 Section 2.
        using (var hmac = new T())
        {
            var overSizedKey = new byte[BlockSize + 1];
            hmac.Key = overSizedKey;
            var actualKey = hmac.Key;
            var expectedKey = CreateHashAlgorithm().ComputeHash(overSizedKey);
            Assert.Equal<byte>(expectedKey, actualKey);

            // Also ensure that the hashing operation uses the adjusted key.
            var data = new byte[100];
            hmac.Key = expectedKey;
            var expectedHash = hmac.ComputeHash(data);

            hmac.Key = overSizedKey;
            var actualHash = hmac.ComputeHash(data);
            Assert.Equal<byte>(expectedHash, actualHash);
        }
    }
}
