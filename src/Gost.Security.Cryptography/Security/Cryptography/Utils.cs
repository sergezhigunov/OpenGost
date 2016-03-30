using System;
using System.Security.Cryptography;
using System.Threading;

namespace Gost.Security.Cryptography
{
    internal static class Utils
    {
        private static RandomNumberGenerator s_randomNumberGenerator;

        internal static RandomNumberGenerator StaticRandomNumberGenerator
            => LazyInitializer.EnsureInitialized(ref s_randomNumberGenerator, () => new RNGCryptoServiceProvider());

        internal static void EraseData<T>(ref T[] data)
            where T : struct
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length);
                data = null;
            }
        }
    }
}
