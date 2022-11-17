using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks;

public abstract class ECDsaBenchmark<T> : IDisposable
    where T : ECDsa, new()
{
    private static RandomNumberGenerator RandomNumberGenerator { get; } = RandomNumberGenerator.Create();

    private readonly byte[] _hash;
    private readonly byte[] _signature;
    private bool _disposed;
    protected T AsymmetricAlgorithm = new();
    private ECCurve Curve { get; }

    protected ECDsaBenchmark(int keySize)
    {
        _hash = new byte[keySize / 8];
        RandomNumberGenerator.GetBytes(_hash);
        AsymmetricAlgorithm.KeySize = keySize;
        Curve = AsymmetricAlgorithm.ExportParameters(true).Curve;
        _signature = AsymmetricAlgorithm.SignHash(_hash);
    }

    [Benchmark]
    public byte[] SignHash() => AsymmetricAlgorithm.SignHash(_hash);

    [Benchmark]
    public bool VerifyHash() => AsymmetricAlgorithm.VerifyHash(_hash, _signature);

    [Benchmark]
    public void GenerateKey() => AsymmetricAlgorithm.GenerateKey(Curve);

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
                AsymmetricAlgorithm.Dispose();
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
