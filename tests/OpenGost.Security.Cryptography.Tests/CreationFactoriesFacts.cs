namespace OpenGost.Security.Cryptography.Tests;

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
        Func<string, object?> factory)
    {
        var objectName = expectedType.Name;
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

    public static TheoryData<Type, Func<string, object?>> ExplicitCreateFactories()
        => new()
        {
            { typeof(GostECDsa), GostECDsa.Create },
            { typeof(Grasshopper), Grasshopper.Create },
            { typeof(Magma), Magma.Create },
            { typeof(Streebog256), Streebog256.Create },
            { typeof(Streebog512), Streebog512.Create },
            { typeof(CMACGrasshopper), CMAC.Create },
            { typeof(CMACMagma), CMAC.Create },
            { typeof(GostECDsa), ECDsa.Create },
            { typeof(GostECDsa), AsymmetricAlgorithm.Create },
            { typeof(Grasshopper), SymmetricAlgorithm.Create },
            { typeof(Magma), SymmetricAlgorithm.Create },
            { typeof(Streebog256), HashAlgorithm.Create },
            { typeof(Streebog512), HashAlgorithm.Create },
            { typeof(CMACGrasshopper), HashAlgorithm.Create },
            { typeof(CMACGrasshopper), KeyedHashAlgorithm.Create },
            { typeof(CMACMagma), HashAlgorithm.Create },
            { typeof(CMACMagma), KeyedHashAlgorithm.Create },
            { typeof(HMACStreebog256), HashAlgorithm.Create },
            { typeof(HMACStreebog256), KeyedHashAlgorithm.Create },
            { typeof(HMACStreebog256), HMAC.Create },
            { typeof(HMACStreebog512), HashAlgorithm.Create },
            { typeof(HMACStreebog512), KeyedHashAlgorithm.Create },
            { typeof(HMACStreebog512), HMAC.Create },
        };

    public static TheoryData<Type, Func<object>> ImplicitCreateFactories()
        => new()
        {
            { typeof(CMACGrasshopper), CMAC.Create },
            { typeof(CMACGrasshopper), CMAC.Create },
            { typeof(GostECDsa), GostECDsa.Create },
            { typeof(Grasshopper), Grasshopper.Create },
            { typeof(Magma), Magma.Create },
            { typeof(Streebog256), Streebog256.Create },
            { typeof(Streebog512), Streebog512.Create },
        };
}
