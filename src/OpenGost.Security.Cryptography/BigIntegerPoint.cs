using System.Numerics;

namespace OpenGost.Security.Cryptography;

internal struct BigIntegerPoint
{
    private static readonly BigInteger _two = 2;
    private static readonly BigInteger _three = 3;

    public BigInteger X { get; private set; }

    public BigInteger Y { get; private set; }

    public BigIntegerPoint(in ECPoint point)
    {
        X = CryptoUtils.UnsignedBigIntegerFromLittleEndian(point.X);
        Y = CryptoUtils.UnsignedBigIntegerFromLittleEndian(point.Y);
    }

    public ECPoint ToECPoint(int size)
    {
        return new ECPoint
        {
            X = CryptoUtils.ToLittleEndian(X, size),
            Y = CryptoUtils.ToLittleEndian(Y, size),
        };
    }
    public static BigIntegerPoint Add(
        in BigIntegerPoint left,
        in BigIntegerPoint right,
        in BigInteger prime)
    {
        var dy = right.Y - left.Y;
        if (dy.Sign == -1)
            dy += prime;
        var dx = right.X - left.X;
        if (dx.Sign == -1)
            dx += prime;
        var lambda = dy * BigInteger.ModPow(dx, prime - _two, prime) % prime;
        if (lambda.Sign == -1)
            lambda += prime;
        var x = (BigInteger.Pow(lambda, 2) - (left.X + right.X)) % prime;
        var y = (lambda * (left.X - x) - left.Y) % prime;
        if (x.Sign == -1)
            x += prime;
        if (y.Sign == -1)
            y += prime;
        return new BigIntegerPoint
        {
            X = x,
            Y = y,
        };
    }

    private static BigIntegerPoint MultipleTwo(
        in BigIntegerPoint value,
        in BigInteger prime,
        in BigInteger a)
    {
        var dy = _three * BigInteger.Pow(value.X, 2) + a;
        var dx = value.Y << 1;
        var lambda = dy * BigInteger.ModPow(dx, prime - _two, prime) % prime;
        var x = (BigInteger.Pow(lambda, 2) - (value.X << 1)) % prime;
        var y = (lambda * (value.X - x) - value.Y) % prime;
        if (x.Sign == -1)
            x += prime;
        if (y.Sign == -1)
            y += prime;
        return new BigIntegerPoint
        {
            X = x,
            Y = y,
        };
    }

    public static BigIntegerPoint Multiply(
        in BigIntegerPoint point,
        in BigInteger multiplier,
        in BigInteger prime,
        in BigInteger a)
    {
        var p = point;
        var result = p;
        var m = multiplier - 1;
        while (m.Sign == 1)
        {
            if (!m.IsEven)
            {
                if (result.X == p.X || result.Y == p.Y)
                    result = MultipleTwo(result, prime, a);
                else
                    result = Add(result, p, prime);
                m--;
            }

            m >>= 1;
            p = MultipleTwo(p, prime, a);
        }
        return result;
    }
}
