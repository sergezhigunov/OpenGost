using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks
{
    public abstract class GostECDsaBenchmark<T>
        where T : GostECDsa, new()
    {
        private static RandomNumberGenerator RandomNumberGenerator { get; } = RandomNumberGenerator.Create();

        private readonly byte[] _hash;
        private readonly byte[] _signature;
        private bool _disposed;
        protected T AsymmetricAlgorithm = new T();

        protected GostECDsaBenchmark()
        {
            _hash = new byte[AsymmetricAlgorithm.KeySize / 8];
            RandomNumberGenerator.GetBytes(_hash);
            _signature = AsymmetricAlgorithm.SignHash(_hash);
        }

        [Benchmark]
        public byte[] SignHash() => AsymmetricAlgorithm.SignHash(_hash);

        [Benchmark]
        public bool DecryptData() => AsymmetricAlgorithm.VerifyHash(_hash, _signature);

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
}
