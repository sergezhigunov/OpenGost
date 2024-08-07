﻿namespace OpenGost.Security.Cryptography.Tests;

public abstract class HashAlgorithmTest<T>
    where T : HashAlgorithm, new()
{
    protected void Verify(string input, string expected)
        => Verify(Convert.FromHexString(input), Convert.FromHexString(expected));

    protected void Verify(byte[] input, byte[] expected)
    {
        byte[] actual;

        using (var hash = new T())
        {
            Assert.True(hash.HashSize > 0);
            actual = hash.ComputeHash(input, 0, input.Length);
        }

        Assert.Equal(expected, actual);
    }
}
