using System;
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

        internal static void EraseData<T>(ref T[] data)
            where T : struct
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length);
                data = null;
            }
        }

        internal static void Xor(byte[] left, int leftOffset, byte[] right, int rightOffset, byte[] result, int resultOffset, int count)
        {
            for (int i = 0; i < count; i++)
                result[resultOffset + i] = (byte)(left[leftOffset + i] ^ right[rightOffset + i]);
        }

        internal static void UInt64ToLittleEndian(byte[] block, ulong[] x, int digits)
        {
            for (int i = 0, j = 0; i < digits; i++, j += 8)
            {
                ulong value = x[i];
                block[j] = (byte)value;
                block[j + 1] = (byte)(value >> 8);
                block[j + 2] = (byte)(value >> 16);
                block[j + 3] = (byte)(value >> 24);
                block[j + 4] = (byte)(value >> 32);
                block[j + 5] = (byte)(value >> 40);
                block[j + 6] = (byte)(value >> 48);
                block[j + 7] = (byte)(value >> 56);
            }
        }

        internal static void UInt64FromLittleEndian(ulong[] x, int digits, byte[] block)
        {
            for (int i = 0, j = 0; i < digits; i++, j += 8)
                x[i] =
                   block[j] |
                    ((ulong)block[j + 1] << 8) |
                    ((ulong)block[j + 2] << 16) |
                    ((ulong)block[j + 3] << 24) |
                    ((ulong)block[j + 4] << 32) |
                    ((ulong)block[j + 5] << 40) |
                    ((ulong)block[j + 6] << 48) |
                    ((ulong)block[j + 7] << 56);
        }


        internal static void UInt32ToBigEndian(uint value, byte[] data, int offset)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        internal static uint UInt32FromBigEndian(byte[] data, int offset)
        {
            return
                data[offset + 3] |
                ((uint)data[offset + 2]) << 8 |
                ((uint)data[offset + 1]) << 16 |
                ((uint)data[offset]) << 24;
        }
    }
}