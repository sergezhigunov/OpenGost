using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Computes the <see cref="Streebog256"/> hash for the input data using the managed implementation.
/// </summary>
[ComVisible(true)]
public class Streebog256Managed : Streebog256
{
    #region Constants

    private static readonly byte[] _defaultIV =
    {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };

    #endregion

    private readonly Streebog512Managed _innerAlgorithm;

    /// <summary>
    /// Initializes a new instance of the <see cref="Streebog256Managed"/> class.
    /// </summary>
    public Streebog256Managed()
    {
        _innerAlgorithm = new Streebog512Managed(_defaultIV);
    }

    /// <summary>
    /// Initializes an instance of <see cref="Streebog256Managed"/>.
    /// </summary>
    public override void Initialize()
    {
        _innerAlgorithm.Initialize();
    }

    /// <summary>
    /// Routes data written to the object into the <see cref="Streebog256"/> hash algorithm for computing the hash.
    /// </summary>
    /// <param name="array">
    /// The input data.
    /// </param>
    /// <param name="ibStart">
    /// The offset into the byte array from which to begin using data.
    /// </param>
    /// <param name="cbSize">
    /// The number of bytes in the array to use as data.
    /// </param>
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
        => _innerAlgorithm.TransformBlock(array, ibStart, cbSize, null, 0);

    /// <summary>
    /// Returns the computed <see cref="Streebog256"/> hash value after all data has been written to the object.
    /// </summary>
    /// <returns>
    /// The computed hash code.
    /// </returns>
    protected override byte[] HashFinal()
    {
        _innerAlgorithm.TransformFinalBlock(
            Array.Empty<byte>(),
            0, 0);
        var hash = new byte[32];
        Buffer.BlockCopy(_innerAlgorithm.Hash, 32, hash, 0, 32);
        HashValue = hash;
        return hash;
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="Streebog256"/> and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> to release both managed and unmanaged resources;
    /// <see langword="false"/> to release only unmanaged resources.
    /// </param>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        _innerAlgorithm.Dispose();
    }
}
