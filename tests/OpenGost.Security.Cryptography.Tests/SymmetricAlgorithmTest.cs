namespace OpenGost.Security.Cryptography.Tests;

public abstract class SymmetricAlgorithmTest<T>
    where T : SymmetricAlgorithm, new()
{
    protected virtual int KeySize => 256;
    protected virtual int BlockSize => 128;

    [Fact]
    public void Constructor_WithoutParameters_InitializesInstance()
    {
        using var algorithm = new T();

        Assert.Equal(KeySize, algorithm.KeySize);
        Assert.Equal(BlockSize, algorithm.BlockSize);
    }

    [Theory]
    [InlineData(default(CipherMode))]
    [InlineData(CipherMode.CTS)]
    public void Key_WhenSetsNull_ThrowsArgumentNullException(CipherMode mode)
    {
        using var algorithm = new T();

        Assert.Throws<CryptographicException>(() => algorithm.Mode = mode);
    }

    [Fact]
    public void GenerateKey_GeneratesValidKey()
    {
        using var algorithm = new T();

        algorithm.GenerateKey();

        var key = algorithm.Key;

        Assert.NotNull(key);
        Assert.Equal(algorithm.KeySize / 8, key.Length);
        Assert.Contains(key, x => x != 0);
    }

    [Fact]
    public void GenerateIV_GeneratesValidKey()
    {
        using var algorithm = new T();

        algorithm.GenerateIV();

        var iv = algorithm.IV;

        Assert.NotNull(iv);
        Assert.Equal(algorithm.FeedbackSize / 8, iv.Length);
        Assert.Contains(iv, x => x != 0);
    }

    public virtual void Verify(
        CipherMode mode,
        PaddingMode padding,
        string plainTextHex,
        string cipherTextHex,
        string keyHex,
        string ivHex)
    {
        byte[]
            plainTextBytes = plainTextHex.HexToByteArray(),
            keyBytes = keyHex.HexToByteArray(),
            ivBytes = ivHex.HexToByteArray();

        using var algorithm = new T { Mode = mode, Padding = padding, Key = keyBytes, IV = ivBytes };
        byte[] encryptedBytes;
        var input = new MemoryStream(plainTextBytes);
        using (var cryptoStream = new CryptoStream(input, algorithm.CreateEncryptor(), CryptoStreamMode.Read))
        using (var output = new MemoryStream())
        {
            cryptoStream.CopyTo(output);
            encryptedBytes = output.ToArray();
        }

        Assert.NotEqual(plainTextBytes, encryptedBytes);

        var cipherTextBytes = cipherTextHex.HexToByteArray();

        Assert.Equal(cipherTextBytes, encryptedBytes);

        byte[] decryptedBytes;
        input = new MemoryStream(encryptedBytes);
        using (var cryptoStream = new CryptoStream(input, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
        using (var output = new MemoryStream())
        {
            cryptoStream.CopyTo(output);
            decryptedBytes = output.ToArray();
        }

        Assert.Equal(plainTextBytes, decryptedBytes);
    }
}
