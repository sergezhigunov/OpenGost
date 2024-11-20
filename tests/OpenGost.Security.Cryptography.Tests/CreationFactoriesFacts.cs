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
            { typeof(CMACGrasshopper), CMAC.Create },
            { typeof(CMACMagma), CMAC.Create },
        };

    public static TheoryData<Type, Func<object>> ImplicitCreateFactories()
        => new()
        {
#pragma warning disable SYSLIB0007
            { typeof(CMACGrasshopper), CMAC.Create },
#pragma warning restore SYSLIB0007
            { typeof(GostECDsa), GostECDsa.Create },
            { typeof(Grasshopper), Grasshopper.Create },
            { typeof(Magma), Magma.Create },
            { typeof(Streebog256), Streebog256.Create },
            { typeof(Streebog512), Streebog512.Create },
        };
}
