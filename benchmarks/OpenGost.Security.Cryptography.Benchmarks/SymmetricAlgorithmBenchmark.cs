using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace OpenGost.Security.Cryptography.Benchmarks
{
    public abstract class SymmetricAlgorithmBenchmark<T> : IDisposable
        where T : SymmetricAlgorithm, new()
    {
        private static readonly byte[] _data =
            Encoding.ASCII.GetBytes("The quick brown fox jumped over the extremely lazy frogs!");

        private readonly byte[] _encryptedData;
        private bool _disposed;

        protected T SymmetricAlgorithm = new T();

        protected SymmetricAlgorithmBenchmark()
        {
            using var encryptor = SymmetricAlgorithm.CreateEncryptor();
            _encryptedData = encryptor.TransformFinalBlock(_data, 0, _data.Length);
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
}
