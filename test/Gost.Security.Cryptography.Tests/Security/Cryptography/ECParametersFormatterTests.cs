using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Xml.Schema;
using Gost.Properties;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static ECHelper;

    public class ECParametersFormatterTests
    {
        private static XmlSchemaSet ECDsaXmlSchemaSet { get; } = LoadECDsaXmlSchemaSet();

        private static XmlSchemaSet LoadECDsaXmlSchemaSet()
        {
            var schemas = new XmlSchemaSet();
            using (var stream = new MemoryStream(Resources.ECDsaXmlSchema))
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
            Curve = new ECCurve
            {
                CurveType = ECCurveType.PrimeShortWeierstrass,
                Prime = "3104000000000000000000000000000000000000000000000000000000000080".HexToByteArray(),
                A = "0700000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                B = "7e3be2dae90c4c512afc72346a6e3f5640efaffb22e0b839e78c93aa98f4bf5f".HexToByteArray(),
                Order = "b3f5cc3a19fc9cc554619792188afe5001000000000000000000000000000080".HexToByteArray(),
                Cofactor = "0100000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                G = new ECPoint
                {
                    X = "0200000000000000000000000000000000000000000000000000000000000000".HexToByteArray(),
                    Y = "c88f7eeabcab962b1267a29c0a7fc9859cd1160e031663bdd44751e6a0a8e208".HexToByteArray(),
                }
            },
            Q = new ECPoint
            {
                X = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f".HexToByteArray(),
                Y = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126".HexToByteArray(),
            },
        };

        [Theory(DisplayName = nameof(ECParametersFormatterTests) + "_" + nameof(WriteAndReadECParameters))]
        [MemberData(nameof(TestECParameters))]
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
