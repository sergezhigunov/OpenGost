using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

internal sealed class HMACCommon : IDisposable
{
    private readonly int _blockSize;
    private readonly HashAlgorithm _hash1;
    private readonly HashAlgorithm _hash2;
    private byte[] _inner = null!;
    private byte[] _outer = null!;
    private bool _hashing;

    public byte[] ActualKey { get; private set; } = null!;
    public int HashSizeInBits => _hash1.HashSize;

    public HMACCommon(string hashAlgorithmId, byte[] key, int blockSize)
    {
        _blockSize = blockSize;
        _hash1 = HashAlgorithm.Create(hashAlgorithmId)!;
        _hash2 = HashAlgorithm.Create(hashAlgorithmId)!;
        ChangeKey(key);
    }

    public void ChangeKey(byte[] key)
    {
        if (_hashing)
            throw new CryptographicException(CryptographyStrings.CryptographicHashKeySet);

        // Perform RFC 2104, section 2 key adjustment.
        if (key.Length > _blockSize)
            ActualKey = _hash1.ComputeHash(key);
        else
            ActualKey = (byte[])key.Clone();
        UpdateIOPadBuffers();
    }

    public void Initialize()
    {
        _hash1.Initialize();
        _hash2.Initialize();
        _hashing = false;
    }

    public void HashCore(byte[] data, int offset, int count)
    {
        if (_hashing == false)
        {
            _hash1.TransformBlock(_inner, 0, _inner.Length, _inner, 0);
            _hashing = true;
        }
        _hash1.TransformBlock(data, offset, count, data, offset);
    }

    public byte[] HashFinal()
    {
        if (_hashing == false)
        {
            _hash1.TransformBlock(_inner, 0, _inner.Length, _inner, 0);
            _hashing = true;
        }
        _hash1.TransformFinalBlock([], 0, 0);
        var hashValue1 = _hash1.Hash!;
        _hash2.TransformBlock(_outer, 0, _outer.Length, _outer, 0);
        _hash2.TransformBlock(hashValue1, 0, hashValue1.Length, hashValue1, 0);
        _hashing = false;
        _hash2.TransformFinalBlock([], 0, 0);
        return _hash2.Hash!;
    }

    public void Dispose()
    {
        Dispose(true);
    }

    public void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hash1?.Dispose();
            _hash2?.Dispose();
            CryptoUtils.EraseData(ref _inner!);
            CryptoUtils.EraseData(ref _outer!);
        }
    }

    private void UpdateIOPadBuffers()
    {
        _inner ??= new byte[_blockSize];
        _outer ??= new byte[_blockSize];

        int i;
        for (i = 0; i < _blockSize; i++)
        {
            _inner[i] = 0x36;
            _outer[i] = 0x5C;
        }
        for (i = 0; i < ActualKey.Length; i++)
        {
            _inner[i] ^= ActualKey[i];
            _outer[i] ^= ActualKey[i];
        }
    }
}
