using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;

namespace Gost.Security.Cryptography
{
    internal static class CryptoUtils
    {
        private static RandomNumberGenerator s_randomNumberGenerator;

        internal static RandomNumberGenerator StaticRandomNumberGenerator
            => LazyInitializer.EnsureInitialized(ref s_randomNumberGenerator, () => new RNGCryptoServiceProvider());

        internal static byte[] GenerateRandomBytes(int size)
        {
            byte[] array = new byte[size];
            StaticRandomNumberGenerator.GetBytes(array);
            return array;
        }

        internal static T[] CloneArray<T>(T[] source)
            => source == null ? null: (T[])source.Clone();

        internal static void EraseData<T>(ref T[] data)
            where T : struct
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length);
                data = null;
            }
        }

        internal static void EraseData<T>(ref T[][] data)
            where T : struct
        {
            if (data != null)
            {
                int length = data.Length;
                for (int i = 0; i < length; i++)
                    EraseData(ref data[i]);

                data = null;
            }
        }

        internal static void Xor(byte[] left, int leftOffset, byte[] right, int rightOffset, byte[] result, int resultOffset, int count)
        {
            for (int i = 0; i < count; i++)
                result[resultOffset + i] = (byte)(left[leftOffset + i] ^ right[rightOffset + i]);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void UInt64ToLittleEndian(byte* block, ulong* x, int digits)
        {
            for (int i = 0, j = 0; i < digits; i++, j += sizeof(ulong))
                UInt64ToLittleEndian(block + j, x[i]);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void UInt64ToLittleEndian(byte* block, ulong value)
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

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void UInt32ToBigEndian(byte* block, uint* x, int digits)
        {
            for (int i = 0, j = 0; i < digits; i++, j += sizeof(uint))
                UInt32ToBigEndian(block + j, x[i]);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe void UInt32ToBigEndian(byte* block, uint value)
        {
            *block = (byte)(value >> 24);
            block[1] = (byte)(value >> 16);
            block[2] = (byte)(value >> 8);
            block[3] = (byte)value;
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal unsafe static void UInt32FromBigEndian(uint* x, int digits, byte* block)
        {
            for (int i = 0, j = 0; i < digits; i++, j += sizeof(uint))
                x[i] = UInt32FromBigEndian(block + j);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe uint UInt32FromBigEndian(byte* block)
            => (uint)(*block << 24) | (uint)(block[1] << 16) | (uint)(block[2] << 8) | (block[3]);

        internal static byte[] ToNormalizedByteArray(BigInteger value, int size)
        {
            if (value < BigInteger.Zero)
                value += (BigInteger.One << size * 8);

            byte[] result = new byte[size];
            for (int i = 0; i < size; i++)
            {
                if (value == BigInteger.Zero)
                    break;
                result[i] = (byte)(value % 256);
                value >>= 8;
            }

            return result;
        }

        internal static ECCurve Clone(this ECCurve curve)
        {
            return new ECCurve
            {
                Prime = CloneArray(curve.Prime),
                A = CloneArray(curve.A),
                B = CloneArray(curve.B),
                Order = CloneArray(curve.Order),
                Cofactor = CloneArray(curve.Cofactor),
                G = Clone(curve.G),
            };
        }

        internal static ECPoint Clone(this ECPoint point)
        {
            return new ECPoint
            {
                X = CloneArray(point.X),
                Y = CloneArray(point.Y)
            };
        }

        internal static BigInteger Normalize(BigInteger value, BigInteger modulus)
            => value >= BigInteger.Zero ? value : value + modulus;
    }
}