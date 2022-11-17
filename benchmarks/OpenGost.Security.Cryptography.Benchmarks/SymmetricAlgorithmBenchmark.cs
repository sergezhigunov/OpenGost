using System.Text;
using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks;

public abstract class SymmetricAlgorithmBenchmark<T> : IDisposable
    where T : SymmetricAlgorithm, new()
{
    private static readonly byte[] _data =
        Encoding.ASCII.GetBytes("The quick brown fox jumped over the extremely lazy frogs!");
    private static readonly byte[] _oneMegabyteData = new byte[1 * 1024 * 1024];
    private readonly byte[] _encryptedData;
    private bool _disposed;

    protected T SymmetricAlgorithm = new() { Padding = PaddingMode.Zeros };

    protected SymmetricAlgorithmBenchmark()
    {
        using var encryptor = SymmetricAlgorithm.CreateEncryptor();
        using var output = new MemoryStream();
        using (var input = new MemoryStream(_data))
        using (var cryptoStream = new CryptoStream(input, encryptor, CryptoStreamMode.Read))
            cryptoStream.CopyTo(output);
        _encryptedData = output.ToArray();
    }

    [Benchmark]
    public byte[] EncryptData()
    {
        using var encryptor = SymmetricAlgorithm.CreateEncryptor();
        using var output = new MemoryStream();
        using (var input = new MemoryStream(_data))
        using (var cryptoStream = new CryptoStream(input, encryptor, CryptoStreamMode.Read))
            cryptoStream.CopyTo(output);
        return output.ToArray();
    }

    [Benchmark]
    public byte[] DecryptData()
    {
        using var decryptor = SymmetricAlgorithm.CreateDecryptor();
        using var output = new MemoryStream();
        using (var input = new MemoryStream(_encryptedData))
        using (var cryptoStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read))
            cryptoStream.CopyTo(output);
        return output.ToArray();
    }

    [Benchmark]
    public byte[] EncryptOneMegabyteData()
    {
        using var encryptor = SymmetricAlgorithm.CreateEncryptor();
        using var output = new MemoryStream();
        using (var input = new MemoryStream(_oneMegabyteData))
        using (var cryptoStream = new CryptoStream(input, encryptor, CryptoStreamMode.Read))
            cryptoStream.CopyTo(output);
        return output.ToArray();
    }

    [Benchmark]
    public byte[] DecryptOneMegabyteData()
    {
        using var decryptor = SymmetricAlgorithm.CreateDecryptor();
        using var output = new MemoryStream();
        using (var input = new MemoryStream(_encryptedData))
        using (var cryptoStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read))
            cryptoStream.CopyTo(output);
        return output.ToArray();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
                SymmetricAlgorithm.Dispose();
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
