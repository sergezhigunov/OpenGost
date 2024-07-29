namespace OpenGost.Security.Cryptography.Tests;

public class ECCurveFacts
{
    [Theory]
    [MemberData(nameof(SupportedOidValues))]
    public void CreateFromValue_CreatesValidInstance(string oidValue)
    {
        var curve = ECCurve.CreateFromValue(oidValue);

        ValidateNamedCurve(curve);
        Assert.Equal(oidValue, curve.Oid.Value);
    }

    [Theory]
    [MemberData(nameof(SupportedOidValues))]
    public void CreateFromOid_CreatesValidInstance(string oidValue)
    {
        var curveOid = new Oid(oidValue);

        var curve = ECCurve.CreateFromOid(curveOid);

        ValidateNamedCurve(curve);
        Assert.Equal(curveOid.Value, curve.Oid.Value);
        Assert.Equal(curveOid.FriendlyName, curve.Oid.FriendlyName);
    }

    public static TheoryData<string> SupportedOidValues { get; }
        = new()
        {
            { "1.2.643.7.1.2.1.1.0" },
            { "1.2.643.7.1.2.1.1.1" },
            { "1.2.643.7.1.2.1.1.2" },
            { "1.2.643.7.1.2.1.1.3" },
            { "1.2.643.7.1.2.1.1.4" },
            { "1.2.643.2.2.35.0" },
            { "1.2.643.2.2.35.1" },
            { "1.2.643.2.2.35.2" },
            { "1.2.643.2.2.35.3" },
            { "1.2.643.2.2.36.0" },
            { "1.2.643.2.2.36.1" },
            { "1.2.643.7.1.2.1.2.0" },
            { "1.2.643.7.1.2.1.2.1" },
            { "1.2.643.7.1.2.1.2.2" },
            { "1.2.643.7.1.2.1.2.3" },
        };

    private static void ValidateNamedCurve(ECCurve curve)
    {
        curve.Validate();
        Assert.Equal(ECCurve.ECCurveType.Named, curve.CurveType);
        Assert.True(curve.IsNamed);
        Assert.False(curve.IsPrime);
        Assert.False(curve.IsExplicit);
        Assert.False(curve.IsCharacteristic2);
        Assert.NotNull(curve.Oid);
    }
}
