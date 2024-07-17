﻿namespace OpenGost.Security.Cryptography.Tests;

public class CreationFactoriesFacts
{
    [Theory]
    [MemberData(nameof(ImplicitCreateFactories))]
    public void CreateImplicit_ReturnsValidInstance(Type expectedType, Func<object> factory)
    {
        var obj = factory.Invoke();
        try
        {
            Assert.NotNull(obj);
            Assert.IsAssignableFrom(expectedType, obj);
        }
        finally
        {
            (obj as IDisposable)?.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(ExplicitCreateFactories))]
    public void CreateExplicit_ReturnsValidInstance(
        Type expectedType,
        Func<string, object?> factory,
        string objectName)
    {
        var obj = factory.Invoke(objectName);
        try
        {
            Assert.NotNull(obj);
            Assert.IsAssignableFrom(expectedType, obj);
        }
        finally
        {
            (obj as IDisposable)?.Dispose();
        }
    }

    public static IEnumerable<object?[]> ExplicitCreateFactories()
    {
        static object?[] TestCase(Type type, Func<string, object?> factory)
            => [type, factory, type.Name];

        return
        [
            TestCase(typeof(GostECDsa), GostECDsa.Create),
            TestCase(typeof(Grasshopper), Grasshopper.Create),
            TestCase(typeof(Magma), Magma.Create),
            TestCase(typeof(Streebog256), Streebog256.Create),
            TestCase(typeof(Streebog512), Streebog512.Create),
            TestCase(typeof(CMACGrasshopper), CMAC.Create),
            TestCase(typeof(CMACMagma), CMAC.Create),
            TestCase(typeof(GostECDsa), ECDsa.Create),
            TestCase(typeof(GostECDsa), AsymmetricAlgorithm.Create),
            TestCase(typeof(Grasshopper), SymmetricAlgorithm.Create),
            TestCase(typeof(Magma), SymmetricAlgorithm.Create),
            TestCase(typeof(Streebog256), HashAlgorithm.Create),
            TestCase(typeof(Streebog512), HashAlgorithm.Create),
            TestCase(typeof(CMACGrasshopper), HashAlgorithm.Create),
            TestCase(typeof(CMACGrasshopper), KeyedHashAlgorithm.Create),
            TestCase(typeof(CMACMagma), HashAlgorithm.Create),
            TestCase(typeof(CMACMagma), KeyedHashAlgorithm.Create),
            TestCase(typeof(HMACStreebog256), HashAlgorithm.Create),
            TestCase(typeof(HMACStreebog256), KeyedHashAlgorithm.Create),
            TestCase(typeof(HMACStreebog256), HMAC.Create),
            TestCase(typeof(HMACStreebog512), HashAlgorithm.Create),
            TestCase(typeof(HMACStreebog512), KeyedHashAlgorithm.Create),
            TestCase(typeof(HMACStreebog512), HMAC.Create),
        ];
    }

    public static IEnumerable<object[]> ImplicitCreateFactories()
    {
        static Func<T> Func<T>(Func<T> func) => func;

        return
        [
                [typeof(CMACGrasshopper), Func(CMAC.Create),],
                [typeof(GostECDsa), Func(GostECDsa.Create),],
                [typeof(Grasshopper), Func(Grasshopper.Create),],
                [typeof(Magma), Func(Magma.Create),],
                [typeof(Streebog256), Func(Streebog256.Create),],
                [typeof(Streebog512), Func(Streebog512.Create),],
            ];
    }
}
