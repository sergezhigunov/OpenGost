using System.Numerics;
using System.Runtime.CompilerServices;

namespace OpenGost.Security.Cryptography;

internal static class CryptoUtils
{
    private static RandomNumberGenerator? _randomNumberGenerator;

    public static RandomNumberGenerator StaticRandomNumberGenerator
        => LazyInitializer.EnsureInitialized(ref _randomNumberGenerator, RandomNumberGenerator.Create)!;

    public static byte[] GenerateRandomBytes(int size)
    {
        var array = new byte[size];
        StaticRandomNumberGenerator.GetBytes(array);
        return array;
    }

    public static T[]? CloneArray<T>(T[]? source)
        => source == null ? null : (T[])source.Clone();

    public static void EraseData<T>(ref T[]? data)
        where T : struct
    {
        if (data != null)
        {
            Array.Clear(data, 0, data.Length);
            data = null;
        }
    }

    public static void Xor(
        byte[] left,
        int leftOffset,
        byte[] right,
        int rightOffset,
        byte[] result,
        int resultOffset,
        int count)
    {
        for (var i = 0; i < count; i++)
            result[resultOffset + i] = (byte)(left[leftOffset + i] ^ right[rightOffset + i]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt64ToLittleEndian(byte* block, ulong* x, int digits)
    {
        for (int i = 0, j = 0; i < digits; i++, j += sizeof(ulong))
            UInt64ToLittleEndian(block + j, x[i]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt64ToLittleEndian(byte* block, ulong value)
    {
        *block = (byte)value;
        block[1] = (byte)(value >> 8);
        block[2] = (byte)(value >> 16);
        block[3] = (byte)(value >> 24);
        block[4] = (byte)(value >> 32);
        block[5] = (byte)(value >> 40);
        block[6] = (byte)(value >> 48);
        block[7] = (byte)(value >> 56);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt32ToBigEndian(byte* block, uint value)
    {
        *block = (byte)(value >> 24);
        block[1] = (byte)(value >> 16);
        block[2] = (byte)(value >> 8);
        block[3] = (byte)value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt32FromBigEndian(uint* x, int digits, byte* block)
    {
        for (int i = 0, j = 0; i < digits; i++, j += sizeof(uint))
            x[i] = UInt32FromBigEndian(block + j);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint UInt32FromBigEndian(byte* block)
        => (uint)(*block << 24) | (uint)(block[1] << 16) | (uint)(block[2] << 8) | (block[3]);

    public static byte[] ToLittleEndian(in BigInteger value, int size)
    {
        var buffer = new byte[size];
        ToLittleEndian(value, buffer, 0, size);
        return buffer;
    }

    public static void ToLittleEndian(BigInteger value, byte[] buffer, int offset, int count)
    {
        var right = offset + count;
        for (var i = offset; i < right; i++)
        {
            if (value == BigInteger.Zero)
                buffer[i] = 0;
            else
            {
                buffer[i] = (byte)(value % 256);
                value >>= 8;
            }
        }
    }

    public static void ToBigEndian(BigInteger value, byte[] buffer, int offset, int count)
    {
        var right = offset + count;
        for (var i = right - 1; i >= offset; i--)
        {
            if (value == BigInteger.Zero)
                buffer[i] = 0;
            else
            {
                buffer[i] = (byte)(value % 256);
                value >>= 8;
            }
        }
    }

    public static ECCurve Clone(this in ECCurve curve)
    {
        if (curve.IsNamed)
            return ECCurve.CreateFromOid(curve.Oid);

        return new ECCurve
        {
            A = CloneArray(curve.A),
            B = CloneArray(curve.B),
            G = Clone(curve.G),
            Order = CloneArray(curve.Order),
            Cofactor = CloneArray(curve.Cofactor),
            Seed = CloneArray(curve.Seed),
            CurveType = curve.CurveType,
            Hash = curve.Hash,
            Prime = CloneArray(curve.Prime),
            Polynomial = CloneArray(curve.Polynomial),
        };
    }

    public static ECPoint Clone(this in ECPoint point)
    {
        return new ECPoint
        {
            X = CloneArray(point.X),
            Y = CloneArray(point.Y),
        };
    }

    public static BigInteger UnsignedBigIntegerFromLittleEndian(byte[] value)
    {
        var length = value.Length;
        if (value[length - 1] >= 0x80)
        {
            var temp = new byte[length + 1];
            Buffer.BlockCopy(value, 0, temp, 0, length);
            value = temp;
        }
        return new BigInteger(value);
    }

    public static BigInteger UnsignedBigIntegerFromBigEndian(byte[] value)
    {
        var length = value.Length;
        if (value[0] < 0x80)
        {
            value = (byte[])value.Clone();
            Array.Reverse(value);
        }
        else
        {
            var temp = new byte[length + 1];
            Buffer.BlockCopy(value, 0, temp, 1, length);
            Array.Reverse(temp);
            value = temp;
        }
        return new BigInteger(value);
    }
}
