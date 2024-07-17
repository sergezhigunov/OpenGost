using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes a Hash-based Message Authentication Code (HMAC)
/// by using the <see cref="Streebog512"/> hash function.
/// </summary>
[ComVisible(true)]
public class HMACStreebog512 : HMAC
{
    private const int BlockSize = 64;
    private readonly HMACCommon _hmacCommon;

    /// <summary>
    /// Gets or sets the key to use in the hash algorithm.
    /// </summary>
    /// <returns>
    /// The key to use in the hash algorithm.
    /// </returns>
    /// <exception cref="CryptographicException">
    /// An attempt is made to change the <see cref="Key"/> property after hashing has begun.
    /// </exception>
    public override byte[] Key
    {
        set
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(value);
#else
            if (value is null)
                throw new ArgumentNullException(nameof(value));
#endif

            _hmacCommon.ChangeKey(value);
            base.Key = _hmacCommon.ActualKey;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HMACStreebog512"/>
    /// class with a randomly generated key.
    /// </summary>
    public HMACStreebog512()
        : this(CryptoUtils.GenerateRandomBytes(BlockSize))
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="HMACStreebog512"/>
    /// class with the specified key data.
    /// </summary>
    /// <param name="key">
    /// The secret key for <see cref="HMACStreebog512"/> encryption.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="key"/> parameter is <see langword="null"/>.
    /// </exception>
    public HMACStreebog512(byte[] key)
    {
#if NET6_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(key);
#else
            if (key is null)
                throw new ArgumentNullException(nameof(key));
#endif

        HashName = CryptoConstants.Streebog512AlgorithmName;
        _hmacCommon = new HMACCommon(CryptoConstants.Streebog512AlgorithmName, key, BlockSize);
        base.Key = _hmacCommon.ActualKey;
        BlockSizeValue = BlockSize;
        HashSizeValue = _hmacCommon.HashSizeInBits;
    }

    /// <summary>
    /// Releases unmanaged resources used by the <see cref="HMACStreebog512"/> object
    /// and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> to release both managed and unmanaged resources;
    /// <see langword="false"/> to release only unmanaged resources.
    /// </param>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _hmacCommon.Dispose();

        base.Dispose(disposing);
    }

    /// <summary>
    /// Routes data written to the object into the <see cref="HMACStreebog512"/> hash
    /// algorithm for computing the hash.
    /// </summary>
    /// <param name="rgb">
    /// The input data.
    /// </param>
    /// <param name="ib">
    /// The offset into the byte array from which to begin using data.
    /// </param>
    /// <param name="cb">
    /// The number of bytes in the array to use as data.
    /// </param>
    protected override void HashCore(byte[] rgb, int ib, int cb)
    {
        _hmacCommon.HashCore(rgb, ib, cb);
    }

    /// <summary>
    /// Finalizes the hash computation after the last data is processed by the cryptographic
    /// stream object.
    /// </summary>
    /// <returns>
    /// The computed hash code.
    /// </returns>
    protected override byte[] HashFinal()
    {
        return _hmacCommon.HashFinal();
    }

    /// <summary>
    /// Initializes an instance of the default implementation of <see cref="HMACStreebog512"/>.
    /// </summary>
    public override void Initialize()
    {
        _hmacCommon.Initialize();
    }
}
