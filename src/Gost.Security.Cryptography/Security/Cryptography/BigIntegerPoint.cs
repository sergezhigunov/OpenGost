using System.Numerics;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    internal struct BigIntegerPoint
    {
        private static readonly BigInteger
            s_two = 2,
            s_three = 3;

        public BigInteger X { get; private set; }

        public BigInteger Y { get; private set; }

        public BigIntegerPoint(ECPoint point, BigInteger modulus)
        {
            X = Normalize(new BigInteger(point.X), modulus);
            Y = Normalize(new BigInteger(point.Y), modulus);
        }

        public ECPoint ToECPoint(int keySize)
        {
            int size = keySize / 8;

            return new ECPoint
            {
                X = ToNormalizedByteArray(X, size),
                Y = ToNormalizedByteArray(Y, size),
            };
        }

        public static BigIntegerPoint Add(BigIntegerPoint left, BigIntegerPoint right, BigInteger prime)
        {
            BigInteger
                dy = Normalize(right.Y - left.Y, prime),
                dx = Normalize(right.X - left.X, prime),
                lambda = Normalize((dy * BigInteger.ModPow(dx, prime - s_two, prime)) % prime, prime),
                x = Normalize((BigInteger.Pow(lambda, 2) - left.X - right.X) % prime, prime);

            return new BigIntegerPoint()
            {
                X = x,
                Y = Normalize((lambda * (left.X - x) - left.Y) % prime, prime),
            };
        }

        private static BigIntegerPoint MultipleTwo(BigIntegerPoint value, BigInteger prime, BigInteger a)
        {
            BigInteger
                dy = Normalize(s_three * BigInteger.Pow(value.X, 2) + a, prime),
                dx = Normalize(s_two * value.Y, prime),
                lambda = (dy * BigInteger.ModPow(dx, prime - s_two, prime)) % prime,
                x = Normalize((BigInteger.Pow(lambda, 2) - s_two * value.X) % prime, prime);

            return new BigIntegerPoint
            {
                X = x,
                Y = Normalize((lambda * (value.X - x) - value.Y) % prime, prime)
            };
        }

        public static BigIntegerPoint Multiply(BigIntegerPoint point, BigInteger multiplier, BigInteger prime, BigInteger a)
        {
            BigIntegerPoint result = point;
            multiplier--;

            while (multiplier > BigInteger.Zero)
            {
                if ((multiplier % s_two) != BigInteger.Zero)
                {
                    if ((result.X == point.X) && (result.Y == point.Y))
                        result = MultipleTwo(result, prime, a);
                    else
                        result = Add(result, point, prime);
                    multiplier--;
                }

                multiplier /= s_two;
                point = MultipleTwo(point, prime, a);
            }

            return result;
        }
    }
}
