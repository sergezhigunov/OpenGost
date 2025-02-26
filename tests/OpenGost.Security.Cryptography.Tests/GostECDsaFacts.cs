namespace OpenGost.Security.Cryptography.Tests;

public class GostECDsaFacts
{
    [Fact]
    public void Create_Parameterless_CreatesDefaultImplementation()
    {
        using var algorithm = GostECDsa.Create();

        Assert.IsType<GostECDsaManaged>(algorithm, true);
    }

    [Fact]
    public void Create_WithCurve_CreatesDefaultImplementation()
    {
        var curve = ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.1");

        using var algorithm = GostECDsa.Create(curve);

        Assert.IsType<GostECDsaManaged>(algorithm, true);
        Assert.Equal(256, algorithm.KeySize);
        var parameters = algorithm.ExportParameters(true);
        Assert.NotNull(parameters.D);
        Assert.NotNull(parameters.Q.X);
        Assert.NotNull(parameters.Q.Y);
        var actualCurve = parameters.Curve;
        Assert.True(actualCurve.IsNamed);
        Assert.NotNull(actualCurve.Oid);
        Assert.Equal(curve.Oid.Value, actualCurve.Oid.Value);
    }

    [Fact]
    public void Create_WithParameters_CreatesDefaultImplementation()
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.0"),
            Q = new ECPoint
            {
                X = Convert.FromHexString("0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f"),
                Y = Convert.FromHexString("da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126"),
            },
            D = Convert.FromHexString("283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a"),
        };

        using var algorithm = GostECDsa.Create(parameters);

        Assert.IsType<GostECDsaManaged>(algorithm, true);
        Assert.Equal(256, algorithm.KeySize);
        var actualParameters = algorithm.ExportParameters(true);
        Assert.NotNull(actualParameters.D);
        Assert.Equal(parameters.D, actualParameters.D);
        Assert.NotSame(parameters.D, actualParameters.D);
        Assert.NotNull(actualParameters.Q.X);
        Assert.Equal(parameters.Q.X, actualParameters.Q.X);
        Assert.NotSame(parameters.Q.X, actualParameters.Q.X);
        Assert.NotNull(actualParameters.Q.Y);
        Assert.Equal(parameters.Q.Y, actualParameters.Q.Y);
        Assert.NotSame(parameters.Q.Y, actualParameters.Q.Y);
        var actualCurve = parameters.Curve;
        Assert.True(actualCurve.IsNamed);
        Assert.NotNull(actualCurve.Oid);
        Assert.Equal(parameters.Curve.Oid.Value, actualCurve.Oid.Value);
    }
}
