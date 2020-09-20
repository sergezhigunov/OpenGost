using System;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks
{
    public abstract class HashAlgorithmBenchmark<T> : IDisposable
        where T : HashAlgorithm, new()
    {
        private static readonly byte[] _data =
            Encoding.ASCII.GetBytes("The quick brown fox jumped over the extremely lazy frogs!");
        private bool _disposed;

        protected T HashAlgorithm { get; } = new T();

        [Benchmark]
        public byte[] HashData() => HashAlgorithm.ComputeHash(_data);

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
}
