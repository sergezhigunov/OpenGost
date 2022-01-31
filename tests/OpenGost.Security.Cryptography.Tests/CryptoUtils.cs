using System;

namespace OpenGost.Security.Cryptography.Tests;

internal static class CryptoUtils
{
    private static readonly Random _random = new();

    public static byte[] GenerateRandomBytes(int size)
    {
        var array = new byte[size];
        _random.NextBytes(array);
        return array;
    }
}
