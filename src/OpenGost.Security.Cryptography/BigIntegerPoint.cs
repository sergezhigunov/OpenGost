using System.Numerics;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography;

internal struct BigIntegerPoint
{
    private static readonly BigInteger
        _two = 2,
        _three = 3;

    public BigInteger X { get; private set; }

    public BigInteger Y { get; private set; }

    public BigIntegerPoint(ECPoint point, BigInteger modulus)
    {
        X = CryptoUtils.Normalize(new BigInteger(point.X), modulus);
        Y = CryptoUtils.Normalize(new BigInteger(point.Y), modulus);
    }

    public ECPoint ToECPoint(int size)
    {
        return new ECPoint
        {
            X = CryptoUtils.ToNormalizedByteArray(X, size),
            Y = CryptoUtils.ToNormalizedByteArray(Y, size),
        };
    }

    public static BigIntegerPoint Add(BigIntegerPoint left, BigIntegerPoint right, BigInteger prime)
    {
        BigInteger
            dy = CryptoUtils.Normalize(right.Y - left.Y, prime),
            dx = CryptoUtils.Normalize(right.X - left.X, prime),
            lambda = CryptoUtils.Normalize((dy * BigInteger.ModPow(dx, prime - _two, prime)) % prime, prime),
            x = CryptoUtils.Normalize((BigInteger.Pow(lambda, 2) - left.X - right.X) % prime, prime);

        return new BigIntegerPoint()
        {
            X = x,
            Y = CryptoUtils.Normalize((lambda * (left.X - x) - left.Y) % prime, prime),
        };
    }

    private static BigIntegerPoint MultipleTwo(BigIntegerPoint value, BigInteger prime, BigInteger a)
    {
        BigInteger
            dy = CryptoUtils.Normalize(_three * BigInteger.Pow(value.X, 2) + a, prime),
            dx = CryptoUtils.Normalize(_two * value.Y, prime),
            lambda = (dy * BigInteger.ModPow(dx, prime - _two, prime)) % prime,
            x = CryptoUtils.Normalize((BigInteger.Pow(lambda, 2) - _two * value.X) % prime, prime);

        return new BigIntegerPoint
        {
            X = x,
            Y = CryptoUtils.Normalize((lambda * (value.X - x) - value.Y) % prime, prime)
        };
    }

    public static BigIntegerPoint Multiply(
        BigIntegerPoint point,
        BigInteger multiplier,
        BigInteger prime,
        BigInteger a)
    {
        var result = point;
        multiplier--;

        while (multiplier > BigInteger.Zero)
        {
            if ((multiplier % _two) != BigInteger.Zero)
            {
                if ((result.X == point.X) && (result.Y == point.Y))
                    result = MultipleTwo(result, prime, a);
                else
                    result = Add(result, point, prime);
                multiplier--;
            }

            multiplier /= _two;
            point = MultipleTwo(point, prime, a);
        }

        return result;
    }
}
