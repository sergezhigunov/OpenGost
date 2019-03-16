using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Xml;
using System.Xml.Schema;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    using static ECHelper;

    public class ECParametersFormatterTests
    {
        [ExcludeFromCodeCoverage]
        private static XmlSchemaSet ECDsaXmlSchemaSet { get; } = LoadECDsaXmlSchemaSet();

        [ExcludeFromCodeCoverage]
        private static XmlSchemaSet LoadECDsaXmlSchemaSet()
        {
            var schemas = new XmlSchemaSet();
            using (var stream = ResourceUtils.GetXmlResource("OpenGost.Security.Cryptography.Tests.ECDsa.xsd"))
                schemas.Add(XmlSchema.Read(stream, null));
            schemas.Compile();
            return schemas;
        }

        public static ECParameters TestNamedParameters { get; } = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.643.7.1.2.1.1.0"),
            Q = new ECPoint
            {
                X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
                Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
            },
        };

        public static ECParameters TestPrimeShortWeierstrassParameters { get; } = new ECParameters
        {
            Curve = ECCurveOidMap.GetExplicitCurveByOid("1.2.643.7.1.2.1.1.0"),
            Q = new ECPoint
            {
                X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
                Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
            },
        };

        [Theory]
        [MemberData(nameof(TestECParameters))]
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        public void WriteAndReadECParameters(ECParameters parameters, int keySize)
        {
            parameters.Validate();

            string xmlString = ECParametersFormatter.ToXmlString(parameters);

            Assert.False(string.IsNullOrEmpty(xmlString));

           // TODO: fix big integer value validation
           var settings = new XmlReaderSettings
           {
               ConformanceLevel = ConformanceLevel.Document,
               //ValidationType = ValidationType.Schema,
               //Schemas = ECDsaXmlSchemaSet,
               //ValidationFlags =
               //    XmlSchemaValidationFlags.ProcessInlineSchema |
               //    XmlSchemaValidationFlags.ProcessSchemaLocation |
               //    XmlSchemaValidationFlags.ReportValidationWarnings,
           };

            using (var textReader = new StringReader(xmlString))
            using (var reader = XmlReader.Create(textReader, settings))
                while (reader.Read()) ;

            ECParameters newParameters = ECParametersFormatter.FromXml(xmlString, keySize);

            AssertEqual(parameters, newParameters, false);
        }

        public static IEnumerable<object[]> TestECParameters()
        {
            return new[]
            {
                new object[] { TestNamedParameters, 32 },
                new object[] { TestPrimeShortWeierstrassParameters, 32 }
            };
        }
    }
}
