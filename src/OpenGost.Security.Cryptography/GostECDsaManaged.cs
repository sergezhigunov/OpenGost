using System.Numerics;
using System.Runtime.InteropServices;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Provides a managed implementation of the <see cref="GostECDsa"/> algorithm.
/// </summary>
[ComVisible(true)]
public sealed class GostECDsaManaged : GostECDsa
{
    private ECCurve _curve;
    private ECPoint _publicKey;
    private byte[]? _privateKey;
    private bool
        _parametersSet,
        _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
    /// with a random key pair.
    /// </summary>
    public GostECDsaManaged()
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
    /// with a specified <see cref="ECParameters"/>.
    /// </summary>
    /// <param name="parameters">
    /// The elliptic curve parameters. Valid key size is 512 bits.
    /// </param>
    /// <exception cref="CryptographicException">
    /// <paramref name="parameters"/> specifies an invalid key length.
    /// </exception>
    public GostECDsaManaged(ECParameters parameters)
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

        GenerateKey(curve, out var publicKey, out var privateKey);

        CryptoUtils.EraseData(ref _privateKey);
        _curve = curve.Clone();
        KeySize = privateKey.Length * 8;
        _publicKey = publicKey;
        _privateKey = privateKey;
        _parametersSet = true;
    }

    private static void GenerateKey(
        in ECCurve curve,
        out ECPoint publicKey,
        out byte[] privateKey)
    {
        var explicitCurve = GetExplicitCurve(curve);
        int size = explicitCurve.Prime!.Length;
        var prime = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Prime);
        var subgroupOrder = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Order!) /
            CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Cofactor!);
        var a = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.A!);
        privateKey = CryptoUtils.GenerateRandomBytes(size);
        var key = CryptoUtils.UnsignedBigIntegerFromLittleEndian(privateKey) % subgroupOrder;
        CryptoUtils.ToLittleEndian(key, privateKey, 0, size);
        var basePoint = new BigIntegerPoint(explicitCurve.G);
        var publicKeyPoint = BigIntegerPoint.Multiply(basePoint, key, prime, a);
        publicKey = publicKeyPoint.ToECPoint(size);

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
            GenerateKey(GetDefaultCurve(KeySize));

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
        KeySize = parameters.Q.X!.Length * 8;

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
    /// <exception cref="CryptographicException">
    /// Invalid hash size.
    /// </exception>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);

        ThrowIfDisposed();

        var keySizeInBytes = KeySize / 8;
        if (keySizeInBytes != hash.Length)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidHashSize(keySizeInBytes));

        if (!_parametersSet)
            GenerateKey(GetDefaultCurve(KeySize));
        return SignHash(hash, _curve, _privateKey!);
    }

    private static byte[] SignHash(
        in byte[] hash,
        in ECCurve curve,
        in byte[] privateKey)
    {
        var explicitCurve = GetExplicitCurve(curve);
        var subgroupOrder = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Order!) /
            CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Cofactor!);
        var e = CryptoUtils.UnsignedBigIntegerFromLittleEndian(hash) % subgroupOrder;
        if (e == BigInteger.Zero)
            e = BigInteger.One;
        var prime = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Prime!);
        var a = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.A!);
        var d = CryptoUtils.UnsignedBigIntegerFromLittleEndian(privateKey) % subgroupOrder;
        int size = hash.Length;
        var buffer = new byte[size];
        var basePoint = new BigIntegerPoint(explicitCurve.G);
        BigInteger k, r, s;
        do
        {
            do
            {
                CryptoUtils.StaticRandomNumberGenerator.GetBytes(buffer);
                k = CryptoUtils.UnsignedBigIntegerFromLittleEndian(buffer) % subgroupOrder;
                r = BigIntegerPoint.Multiply(basePoint, k, prime, a).X % subgroupOrder;
            }
            while (r.Sign == 0);
            s = (r * d + k * e) % subgroupOrder;
        }
        while (r.Sign == 0);
        var signature = new byte[size * 2];
        CryptoUtils.ToBigEndian(s, signature, 0, size);
        CryptoUtils.ToBigEndian(r, signature, size, size);
        return signature;
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
    /// <exception cref="CryptographicException">
    /// Invalid hash size.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Invalid signature size.
    /// </exception>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);

        ThrowIfDisposed();

        var keySizeInBytes = KeySize / 8;
        if (keySizeInBytes != hash.Length)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidHashSize(keySizeInBytes));
        var signatureSizeInBytes = keySizeInBytes * 2;
        if (signatureSizeInBytes != signature.Length)
            throw new CryptographicException(
                CryptographyStrings.CryptographicInvalidSignatureSize(signatureSizeInBytes));

        // There is no necessity to generate new parameter, just return false
        if (!_parametersSet)
            return false;

        return VerifyHash(hash, signature, _curve, _publicKey);
    }

    private static bool VerifyHash(
        in byte[] hash,
        in byte[] signature,
        in ECCurve curve,
        in ECPoint publicKey)
    {
        var explicitCurve = GetExplicitCurve(curve);
        var subgroupOrder = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Order!) /
            CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Cofactor!);
        int size = hash.Length;
        var array = new byte[size];
        Buffer.BlockCopy(signature, 0, array, 0, size);
        var s = CryptoUtils.UnsignedBigIntegerFromBigEndian(array);
        if (s.Sign != 1 || s > subgroupOrder)
            return false;
        Buffer.BlockCopy(signature, size, array, 0, size);
        var r = CryptoUtils.UnsignedBigIntegerFromBigEndian(array);
        if (r.Sign != 1 || r > subgroupOrder)
            return false;
        var e = CryptoUtils.UnsignedBigIntegerFromLittleEndian(hash) % subgroupOrder;
        if (e == BigInteger.Zero)
            e = BigInteger.One;
        var v = BigInteger.ModPow(e, subgroupOrder - 2, subgroupOrder) % subgroupOrder;
        var z1 = s * v % subgroupOrder;
        var z2 = (subgroupOrder - r) * v % subgroupOrder;
        var prime = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.Prime!);
        var a = CryptoUtils.UnsignedBigIntegerFromLittleEndian(explicitCurve.A!);
        var c = BigIntegerPoint.Add(
            BigIntegerPoint.Multiply(new BigIntegerPoint(explicitCurve.G), z1, prime, a),
            BigIntegerPoint.Multiply(new BigIntegerPoint(publicKey), z2, prime, a),
            prime);
        return c.X % subgroupOrder == r;
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="GostECDsaManaged"/> class
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

    private static ECCurve GetExplicitCurve(in ECCurve curve)
    {
        return curve.CurveType switch
        {
            ECCurve.ECCurveType.PrimeShortWeierstrass => curve,
            ECCurve.ECCurveType.Named => ECCurveOidMap.GetExplicitCurveByOid(curve.Oid.Value!),
            ECCurve.ECCurveType.Implicit or
            ECCurve.ECCurveType.PrimeTwistedEdwards or
            ECCurve.ECCurveType.PrimeMontgomery or
            ECCurve.ECCurveType.Characteristic2 or
            _ => throw new NotImplementedException(),
        };
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private static ECCurve GetDefaultCurve(int keySize)
        => keySize switch
        {
            512 => ECCurve.CreateFromValue("1.2.643.7.1.2.1.2.1"),
            _ => ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.1"),
        };
}
