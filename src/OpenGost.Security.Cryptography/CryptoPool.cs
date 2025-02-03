using System.Buffers;
using System.Diagnostics;

namespace OpenGost.Security.Cryptography;

internal static class CryptoPool
{
    internal const int ClearAll = -1;

    internal static byte[] Rent(int minimumLength) => ArrayPool<byte>.Shared.Rent(minimumLength);

    internal static void Return(ArraySegment<byte> arraySegment)
    {
        Debug.Assert(arraySegment.Array != null);
        Debug.Assert(arraySegment.Offset == 0);

        Return(arraySegment.Array, arraySegment.Count);
    }

    internal static void Return(byte[] array, int clearSize = ClearAll)
    {
        Debug.Assert(clearSize <= array.Length);
        bool clearWholeArray = clearSize < 0;

        if (!clearWholeArray && clearSize != 0)
        {
            CryptographicOperations.ZeroMemory(array.AsSpan(0, clearSize));
        }

        ArrayPool<byte>.Shared.Return(array, clearWholeArray);
    }
}
