using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Provides a managed implementation of the <see cref="GostECDsa256"/> algorithm.
/// </summary>
[ComVisible(true)]
public sealed class GostECDsa256Managed : GostECDsa256
{
    private static readonly BigInteger _modulus = BigInteger.One << 256;

    private ECCurve _curve;
    private ECPoint _publicKey;
    private byte[]? _privateKey;
    private bool
        _parametersSet,
        _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa256Managed" /> class
    /// with a random key pair.
    /// </summary>
    public GostECDsa256Managed()
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa256Managed" /> class
    /// with a specified <see cref="ECParameters"/>.
    /// </summary>
    /// <param name="parameters">
    /// The elliptic curve parameters. Valid key size is 256 bits.
    /// </param>
    /// <exception cref="CryptographicException">
    /// <paramref name="parameters"/> specifies an invalid key length.
    /// </exception>
    public GostECDsa256Managed(ECParameters parameters)
    {
        ImportParameters(parameters);
    }

    /// <summary>
    /// Generates a new public/private key pair for the specified curve.
    /// </summary>
    /// <param name="curve">
    /// The curve to use.
    /// </param>
    /// <exception cref="CryptographicException">
    /// <paramref name="curve"/> is invalid.
    /// </exception>
    [ComVisible(false)]
    public override void GenerateKey(ECCurve curve)
    {
        curve.Validate();

        GostECDsa512Managed.GenerateKey(curve, _modulus, out var publicKey, out var privateKey);

        CryptoUtils.EraseData(ref _privateKey);
        _curve = curve.Clone();
        _publicKey = publicKey;
        _privateKey = privateKey;
        _parametersSet = true;
    }

    /// <summary>
    /// Exports the <see cref="ECParameters"/> for an <see cref="ECCurve"/>.
    /// </summary>
    /// <param name="includePrivateParameters">
    /// <see langword="true"/> to include private parameters;
    /// otherwise, <see langword="false"/>.</param>
    /// <returns>
    /// An <see cref="ECParameters"/>.
    /// </returns>
    /// <exception cref="CryptographicException">
    /// The key cannot be exported.
    /// </exception>
    [ComVisible(false)]
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        ThrowIfDisposed();

        if (!_parametersSet)
            GenerateKey(GetDefaultCurve());

        return new ECParameters
        {
            Curve = _curve.Clone(),
            Q = _publicKey.Clone(),
            D = includePrivateParameters ? CryptoUtils.CloneArray(_privateKey) : null,
        };
    }

    /// <summary>
    /// Imports the specified <see cref="ECParameters"/>.
    /// </summary>
    /// <param name="parameters">
    /// The curve parameters.
    /// </param>
    /// <exception cref="CryptographicException">
    /// <paramref name="parameters"/> are invalid.
    /// </exception>
    [ComVisible(false)]
    public override void ImportParameters(ECParameters parameters)
    {
        ThrowIfDisposed();

        parameters.Validate();
        KeySize = parameters.Q.X.Length * 8;

        _curve = parameters.Curve.Clone();
        _publicKey = parameters.Q.Clone();
        _privateKey = CryptoUtils.CloneArray(parameters.D);
        _parametersSet = true;
    }

    /// <summary>
    /// Generates a digital signature for the specified hash value.
    /// </summary>
    /// <param name="hash">
    /// The hash value of the data that is being signed.
    /// </param>
    /// <returns>
    /// A digital signature that consists of the given hash value encrypted with the private key.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="hash"/> parameter is <see langword="null"/>.
    /// </exception>
    public override byte[] SignHash(byte[] hash)
    {
        if (hash == null)
            throw new ArgumentNullException(nameof(hash));

        ThrowIfDisposed();

        if (KeySize / 8 != hash.Length)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidHashSize(KeySize / 8));

        if (!_parametersSet)
            GenerateKey(GetDefaultCurve());

        return GostECDsa512Managed.SignHash(hash, _modulus, _curve, _privateKey!);
    }

    /// <summary>
    /// Verifies a digital signature against the specified hash value.
    /// </summary>
    /// <param name="hash">
    /// The hash value of a block of data.
    /// </param>
    /// <param name="signature">
    /// The digital signature to be verified.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the hash value equals the decrypted signature;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="hash"/> parameter is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="signature"/> parameter is <see langword="null"/>.
    /// </exception>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        if (hash == null)
            throw new ArgumentNullException(nameof(hash));
        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        ThrowIfDisposed();

        if (KeySize / 8 != hash.Length)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidHashSize(KeySize / 8));
        if (KeySize / 4 != signature.Length)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidSignatureSize(KeySize / 4));

        // There is no necessity to generate new parameter, just return false
        if (!_parametersSet)
            return false;

        return GostECDsa512Managed.VerifyHash(hash, signature, _modulus, _curve, _publicKey);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="GostECDsa256Managed"/> class
    /// and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/>true to release both managed and unmanaged resources;
    /// <see langword="false"/> to release only unmanaged resources.
    /// </param>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            CryptoUtils.EraseData(ref _privateKey);

            if (disposing)
            {
                CryptoUtils.EraseData(ref _curve.Prime);
                CryptoUtils.EraseData(ref _curve.A);
                CryptoUtils.EraseData(ref _curve.B);
                CryptoUtils.EraseData(ref _curve.Order);
                CryptoUtils.EraseData(ref _curve.Cofactor);
                CryptoUtils.EraseData(ref _publicKey.X);
                CryptoUtils.EraseData(ref _publicKey.Y);
                var g = _curve.G;
                CryptoUtils.EraseData(ref g.X);
                CryptoUtils.EraseData(ref g.Y);
            }
        }

        base.Dispose(disposing);
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);
    }

    private static ECCurve GetDefaultCurve()
        => ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.1");
}
