using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Provides a managed implementation of the <see cref="GostECDsa512"/> algorithm.
    /// </summary>
    [ComVisible(true)]
    public sealed class GostECDsa512Managed : GostECDsa512
    {
        private static readonly BigInteger _modulus = BigInteger.One << 512;

        private ECCurve _curve;
        private ECPoint _publicKey;
        private byte[]? _privateKey;
        private bool
            _parametersSet,
            _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa512Managed" /> class
        /// with a random key pair.
        /// </summary>
        public GostECDsa512Managed()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa512Managed" /> class
        /// with a specified <see cref="ECParameters"/>.
        /// </summary>
        /// <param name="parameters">
        /// The elliptic curve parameters. Valid key size is 512 bits.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="parameters"/> specifies an invalid key length.
        /// </exception>
        public GostECDsa512Managed(ECParameters parameters)
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

            GenerateKey(curve, _modulus, out var publicKey, out var privateKey);

            CryptoUtils.EraseData(ref _privateKey);
            _curve = curve.Clone();
            _publicKey = publicKey;
            _privateKey = privateKey;
            _parametersSet = true;
        }

        internal static void GenerateKey(
            ECCurve curve,
            in BigInteger modulus,
            out ECPoint publicKey,
            out byte[] privateKey)
        {
            if (!curve.IsExplicit)
                curve = ECCurveOidMap.GetExplicitCurveByOid(curve.Oid.Value);

            var prime = CryptoUtils.Normalize(new BigInteger(curve.Prime), modulus);
            var subgroupOrder = CryptoUtils.Normalize(new BigInteger(curve.Order), modulus) /
                CryptoUtils.Normalize(new BigInteger(curve.Cofactor), modulus);
            var a = CryptoUtils.Normalize(new BigInteger(curve.A), modulus);
            int size = curve.Prime.Length;
            privateKey = new byte[size];

            BigInteger key;
            do
            {
                CryptoUtils.StaticRandomNumberGenerator.GetBytes(privateKey);
                key = CryptoUtils.Normalize(new BigInteger(privateKey), modulus);
            }
            while (BigInteger.Zero >= key || key >= subgroupOrder);

            var basePoint = new BigIntegerPoint(curve.G, modulus);
            publicKey = BigIntegerPoint.Multiply(basePoint, key, prime, a).ToECPoint(size);
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

            return SignHash(hash, _modulus, _curve, _privateKey!);
        }

        internal static byte[] SignHash(
            in byte[] hash,
            in BigInteger modulus,
            ECCurve curve,
            in byte[] privateKey)
        {
            if (!curve.IsExplicit)
                curve = ECCurveOidMap.GetExplicitCurveByOid(curve.Oid.Value);
            var subgroupOrder = CryptoUtils.Normalize(new BigInteger(curve.Order), modulus) /
                CryptoUtils.Normalize(new BigInteger(curve.Cofactor), modulus);
            var e = CryptoUtils.Normalize(new BigInteger(hash), modulus) % subgroupOrder;
            if (e == BigInteger.Zero)
                e = BigInteger.One;
            var prime = CryptoUtils.Normalize(new BigInteger(curve.Prime), modulus);
            var a = CryptoUtils.Normalize(new BigInteger(curve.A), modulus);
            var d = CryptoUtils.Normalize(new BigInteger(privateKey), modulus);
            int size = curve.Prime.Length;
            var rgb = new byte[size];

            BigInteger k, r, s;
            do
            {
                do
                {
                    do
                    {
                        CryptoUtils.StaticRandomNumberGenerator.GetBytes(rgb);
                        k = CryptoUtils.Normalize(new BigInteger(rgb), modulus);
                    } while (k <= BigInteger.Zero || k >= subgroupOrder);

                    r = BigIntegerPoint.Multiply(new BigIntegerPoint(curve.G, modulus), k, prime, a).X;
                } while (r == BigInteger.Zero);

                s = (r * d + k * e) % subgroupOrder;
            }
            while (s == BigInteger.Zero);

            var signature = new byte[size * 2];
            var array = s.ToByteArray();
            Buffer.BlockCopy(array, 0, signature, 0, Math.Min(array.Length, size));
            array = r.ToByteArray();
            Buffer.BlockCopy(array, 0, signature, size, Math.Min(array.Length, size));
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

            return VerifyHash(hash, signature, _modulus, _curve, _publicKey);
        }

        internal static bool VerifyHash(
            in byte[] hash,
            in byte[] signature,
            in BigInteger modulus,
            ECCurve curve,
            in ECPoint publicKey)
        {
            if (!curve.IsExplicit)
                curve = ECCurveOidMap.GetExplicitCurveByOid(curve.Oid.Value);
            var size = curve.Prime.Length;
            var subgroupOrder = CryptoUtils.Normalize(new BigInteger(curve.Order), modulus) /
                CryptoUtils.Normalize(new BigInteger(curve.Cofactor), modulus);
            var array = new byte[size];
            Buffer.BlockCopy(signature, 0, array, 0, size);
            var s = CryptoUtils.Normalize(new BigInteger(array), modulus);
            if (s < BigInteger.One || s > subgroupOrder)
                return false;
            Buffer.BlockCopy(signature, size, array, 0, size);
            var r = CryptoUtils.Normalize(new BigInteger(array), modulus);
            if (r < BigInteger.One || r > subgroupOrder)
                return false;
            var e = CryptoUtils.Normalize(new BigInteger(hash), modulus) % subgroupOrder;
            if (e == BigInteger.Zero)
                e = BigInteger.One;
            var v = BigInteger.ModPow(e, subgroupOrder - 2, subgroupOrder);
            var z1 = (s * v) % subgroupOrder;
            var z2 = (subgroupOrder - r) * v % subgroupOrder;
            var prime = CryptoUtils.Normalize(new BigInteger(curve.Prime), modulus);
            var a = CryptoUtils.Normalize(new BigInteger(curve.A), modulus);
            var c = BigIntegerPoint.Add(
                BigIntegerPoint.Multiply(new BigIntegerPoint(curve.G, modulus), z1, prime, a),
                BigIntegerPoint.Multiply(new BigIntegerPoint(publicKey, modulus), z2, prime, a),
                prime);
            return c.X == r;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="GostECDsa512Managed"/> class
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
            => ECCurve.CreateFromValue("1.2.643.7.1.2.1.2.1");
    }
}
