﻿using System;
using System.Security.Cryptography;
using System.Threading;

namespace Gost.Security.Cryptography
{
    using static CryptoConstants;

    internal static class CryptoUtils
    {
        private static RandomNumberGenerator s_randomNumberGenerator;
        private static bool s_gostCryptographyConfigured;

        internal static RandomNumberGenerator StaticRandomNumberGenerator
            => LazyInitializer.EnsureInitialized(ref s_randomNumberGenerator, () => new RNGCryptoServiceProvider());

        private static object ConfigurationLock { get; } = new object();

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

        internal static void UInt64ToLittleEndian(ulong value, byte[] data, int offset)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
            data[offset + 4] = (byte)(value >> 32);
            data[offset + 5] = (byte)(value >> 40);
            data[offset + 6] = (byte)(value >> 48);
            data[offset + 7] = (byte)(value >> 56);
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

        internal static object CreateFromName(string name)
        {
            EnsureGostCryptographyConfigured();

            return CryptoConfig.CreateFromName(name);
        }

        private static void EnsureGostCryptographyConfigured()
        {
            if (s_gostCryptographyConfigured)
                return;
            lock (ConfigurationLock)
            {
                if (s_gostCryptographyConfigured)
                    return;

                ConfigureGostCryptography();
                s_gostCryptographyConfigured = true;
            }
        }

        private static void ConfigureGostCryptography()
        {
            CryptoConfig.AddAlgorithm(typeof(GrasshopperManaged), GrasshopperManagedAlgorithmFullName, GrasshopperManagedAlgorithmName);
            CryptoConfig.AddAlgorithm(typeof(MagmaManaged), MagmaManagedAlgorithmFullName, MagmaManagedAlgorithmName);
            CryptoConfig.AddAlgorithm(typeof(Streebog512Managed), Streebog512ManagedAlgorithmFullName, Streebog512ManagedAlgorithmName);
            CryptoConfig.AddAlgorithm(typeof(Streebog256Managed), Streebog256ManagedAlgorithmFullName, Streebog256ManagedAlgorithmName);
        }
    }
}
