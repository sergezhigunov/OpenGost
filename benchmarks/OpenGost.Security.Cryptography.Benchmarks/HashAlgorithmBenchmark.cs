using System.Text;
using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks;

public abstract class HashAlgorithmBenchmark<T> : IDisposable
    where T : HashAlgorithm, new()
{
    private static readonly byte[] _data =
        Encoding.ASCII.GetBytes("The quick brown fox jumped over the extremely lazy frogs!");
    private static readonly byte[] _oneMegabyteData = new byte[1 * 1024 * 1024];
    private bool _disposed;

    protected T HashAlgorithm { get; } = new T();

    [Benchmark]
    public byte[] HashEmptyData() => HashAlgorithm.ComputeHash(Array.Empty<byte>());

    [Benchmark]
    public byte[] HashData() => HashAlgorithm.ComputeHash(_data);

    [Benchmark]
    public byte[] HashOneMegabyteData() => HashAlgorithm.ComputeHash(_oneMegabyteData);

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
                HashAlgorithm.Dispose();
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
