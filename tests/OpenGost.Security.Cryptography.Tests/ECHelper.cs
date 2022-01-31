using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography.Tests;

[ExcludeFromCodeCoverage]
internal static class ECHelper
{
    public static void AssertEqual(ECPoint expected, ECPoint actual)
    {
        Assert.Equal(expected.X, actual.X);
        Assert.Equal(expected.Y, actual.Y);
    }

    public static void AssertEqual(ECCurve expected, ECCurve actual)
    {
        Assert.Equal(expected.A, actual.A);
        Assert.Equal(expected.B, actual.B);
        AssertEqual(expected.G, actual.G);
        Assert.Equal(expected.Order, actual.Order);
        Assert.Equal(expected.Cofactor, actual.Cofactor);
        Assert.Equal(expected.Seed, actual.Seed);
        Assert.Equal(expected.Hash, actual.Hash);
        Assert.Equal(expected.Polynomial, actual.Polynomial);
        Assert.Equal(expected.Prime, actual.Prime);
        if (expected.IsNamed)
            AssertEqual(expected.Oid, actual.Oid);
    }

    public static void AssertEqual(ECParameters expected, ECParameters actual, bool shouldComparePrivateData)
    {
        AssertEqual(expected.Curve, actual.Curve);
        AssertEqual(expected.Q, actual.Q);
        if (shouldComparePrivateData)
            Assert.Equal(expected.D, actual.D);
    }

    public static void AssertEqual(Oid expected, Oid actual)
    {
        Assert.Equal(expected.Value, actual.Value);
        Assert.Equal(expected.FriendlyName, actual.FriendlyName);
    }
}
