using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static Buffer;

    /// <summary>
    /// Provides a managed implementation of the <see cref="GostECDsa"/> algorithm. 
    /// </summary>
    public sealed class GostECDsaManaged : GostECDsa
    {
        private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(256, 512, 256) };
        private static BigInteger
            s_two = 2,
            s_three = 3,
            s_twoPow256 = BigInteger.One << 256,
            s_twoPow512 = BigInteger.One << 512;

        private ECParameters _parameters;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
        /// with a random key pair.
        /// </summary>
        public GostECDsaManaged()
            : this(512)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
        /// with a random key pair, using the specified key size.
        /// </summary>
        /// <param name="keySize">
        /// The size of the key. Valid key sizes are 256 and 512 bits.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="keySize"/> specifies an invalid length.
        /// </exception>
        public GostECDsaManaged(int keySize)
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySize = keySize;

            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaManaged" /> class
        /// with a specified <see cref="ECParameters"/>.
        /// </summary>
        /// <param name="parameters">
        /// The elliptic curve parameters. Valid key sizes are 256 and 512 bits.
        /// </param>
        /// <exception cref="CryptographicException">
        /// <paramref name="parameters"/> specifies an invalid key length.
        /// </exception>
        public GostECDsaManaged(ECParameters parameters)
        {
            LegalKeySizesValue = s_legalKeySizes;
            parameters.Validate();
            KeySize = parameters.Q.X.Length * 8;

            _parameters = parameters;
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
        /// The <paramref name="hash"/> parameter is <c>null</c>.
        /// </exception>
        public override byte[] SignHash(byte[] hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));

            throw new NotImplementedException();
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
        /// <c>true</c> if the hash value equals the decrypted signature;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="hash"/> parameter is <c>null</c>.
        /// -or-
        /// The <paramref name="signature"/> parameter is <c>null</c>.
        /// </exception>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (signature == null) throw new ArgumentNullException(nameof(signature));

            int keySizeInByted = KeySize / 8;

            ECCurve curve = _parameters.Curve;

            BigInteger
                modulus = keySizeInByted == 64 ? s_twoPow512 : s_twoPow256,
                subgroupOrder = Normalize(new BigInteger(curve.Order), modulus) / Normalize(new BigInteger(curve.Cofactor), modulus);

            byte[] array = new byte[keySizeInByted];

            BlockCopy(signature, 0, array, 0, keySizeInByted);
            BigInteger s = Normalize(new BigInteger(array), modulus);
            if (s < BigInteger.One || s > subgroupOrder)
                return false;

            BlockCopy(signature, keySizeInByted, array, 0, keySizeInByted);
            BigInteger r = Normalize(new BigInteger(array), modulus);
            if (r < BigInteger.One || r > subgroupOrder)
                return false;

            BigInteger e = Normalize(new BigInteger(hash), modulus) % subgroupOrder;

            if (e == BigInteger.Zero)
                e = BigInteger.One;

            BigInteger
                v = BigInteger.ModPow(e, subgroupOrder - s_two, subgroupOrder),
                z1 = (s * v) % subgroupOrder,
                z2 = (subgroupOrder - r) * v % subgroupOrder,
                prime = Normalize(new BigInteger(curve.Prime), modulus),
                a = Normalize(new BigInteger(curve.A), modulus);

            ECPoint c = ECPoint.Add(
                ECPoint.Multiply(new ECPoint(curve.G, modulus), z1, prime, a),
                ECPoint.Multiply(new ECPoint(_parameters.Q, modulus), z2, prime, a),
                prime,
                a);

            return c.X == r;
        }

        private static BigInteger Normalize(BigInteger value, BigInteger order)
            => value >= BigInteger.Zero ? value : value + order;

        private struct ECPoint
        {
            public BigInteger X { get; private set; }

            public BigInteger Y { get; private set; }

            public ECPoint(Cryptography.ECPoint point, BigInteger modulus)
            {
                X = Normalize(new BigInteger(point.X), modulus);
                Y = Normalize(new BigInteger(point.Y), modulus);
            }

            public static ECPoint Add(ECPoint left, ECPoint right, BigInteger prime, BigInteger a)
            {
                BigInteger
                    dy = Normalize(right.Y - left.Y, prime),
                    dx = Normalize(right.X - left.X, prime),
                    lambda = Normalize((dy * BigInteger.ModPow(dx, prime - s_two, prime)) % prime, prime),
                    x = Normalize((BigInteger.Pow(lambda, 2) - left.X - right.X) % prime, prime);

                return new ECPoint()
                {
                    X = x,
                    Y = Normalize((lambda * (left.X - x) - left.Y) % prime, prime),
                };
            }

            private static ECPoint MultipleTwo(ECPoint value, BigInteger prime, BigInteger a)
            {
                BigInteger
                    dy = Normalize(s_three * BigInteger.Pow(value.X, 2) + a, prime),
                    dx = Normalize(s_two * value.Y, prime),
                    lambda = (dy * BigInteger.ModPow(dx, prime - s_two, prime)) % prime,
                    x = Normalize((BigInteger.Pow(lambda, 2) - s_two * value.X) % prime, prime);

                return new ECPoint
                {
                    X = x,
                    Y = Normalize((lambda * (value.X - x) - value.Y) % prime, prime)
                };
            }

            public static ECPoint Multiply(ECPoint point, BigInteger multiplier, BigInteger prime, BigInteger a)
            {
                ECPoint result = point;
                multiplier--;

                while (multiplier > BigInteger.Zero)
                {
                    if ((multiplier % s_two) != BigInteger.Zero)
                    {
                        if ((result.X == point.X) && (result.Y == point.Y))
                            result = MultipleTwo(result, prime, a);
                        else
                            result = Add(result, point, prime, a);
                        multiplier--;
                    }

                    multiplier /= s_two;
                    point = MultipleTwo(point, prime, a);
                }

                return result;
            }
        }
    }
}