using System.Reflection;

namespace OpenGost.Security.Cryptography.Tests;

public class CreationFactoriesFacts
{
    [Theory]
    [InlineData(typeof(GostECDsaManaged), typeof(GostECDsa))]
    [InlineData(typeof(GrasshopperManaged), typeof(Grasshopper))]
    [InlineData(typeof(MagmaManaged), typeof(Magma))]
    [InlineData(typeof(Streebog256Managed), typeof(Streebog256))]
    [InlineData(typeof(Streebog512Managed), typeof(Streebog512))]
    public void CreateImplicit_ReturnsValidInstance(Type expectedType, Type algorithmType)
    {
        var factory = algorithmType.GetMethod("Create", BindingFlags.Static | BindingFlags.Public, []);
        Assert.NotNull(factory);
        Assert.Equal(algorithmType, factory.ReturnType);

        var obj = factory.Invoke(null, null);
        Assert.NotNull(obj);
        try
        {
            Assert.IsType(expectedType, obj, exactMatch: false);
        }
        finally
        {
            (obj as IDisposable)?.Dispose();
        }
    }
}
