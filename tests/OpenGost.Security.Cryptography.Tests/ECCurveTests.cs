using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class ECCurveTests : CryptoConfigRequiredTest
    {
        [Theory]
        [MemberData(nameof(SupportedOidValues))]
        public void CreateFromValue(string oidValue)
        {
            var curve = ECCurve.CreateFromValue(oidValue);

            ValidateNamedCurve(curve);
            Assert.Equal(oidValue, curve.Oid.Value);
        }

        [Theory]
        [MemberData(nameof(SupportedOids))]
        public void CreateFromOid(Oid curveOid)
        {
            var curve = ECCurve.CreateFromOid(curveOid);

            ValidateNamedCurve(curve);
            Assert.Equal(curveOid.Value, curve.Oid.Value);
            Assert.Equal(curveOid.FriendlyName, curve.Oid.FriendlyName);
        }

        public static IEnumerable<object[]> SupportedOidValues()
        {
            foreach (var oidValue in new[]
            {
                "1.2.643.7.1.2.1.1.0",
                "1.2.643.7.1.2.1.1.1",
                "1.2.643.2.2.35.0",
                "1.2.643.2.2.35.1",
                "1.2.643.2.2.35.2",
                "1.2.643.2.2.35.3",
                "1.2.643.2.2.36.0",
                "1.2.643.7.1.2.1.2.0",
                "1.2.643.7.1.2.1.2.1",
                "1.2.643.7.1.2.1.2.2",
                "1.2.643.7.1.2.1.2.3",
            })
                yield return new[] { oidValue };
        }

        public static IEnumerable<object[]> SupportedOids()
        {
            foreach (var oidValue in SupportedOidValues())
                yield return new[] { new Oid((string)oidValue.First())  };
        }

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
}
