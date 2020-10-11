using System;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography
{
    internal static class ECParametersFormatter
    {
        private const string ATag = "A";
        private const string BasePointParamsTag = "BasePointParams";
        private const string BasePointTag = "BasePoint";
        private const string BTag = "B";
        private const string CofactorTag = "Cofactor";
        private const string CurveParamsTag = "CurveParams";
        private const string DomainParametersTag = "DomainParameters";
        private const string ECDsaKeyValueTag = "ECDSAKeyValue";
        private const string ExplicitParamsTag = "ExplicitParams";
        private const string FieldParamsTag = "FieldParams";
        private const string NamedCurveTag = "NamedCurve";
        private const string Namespace = "http://www.w3.org/2001/04/xmldsig-more#";
        private const string OrderTag = "Order";
        private const string PrimeFieldElemTypeValue = "PrimeFieldElemType";
        private const string PrimeFieldParamsTypeValue = "PrimeFieldParamsType";
        private const string PTag = "P";
        private const string PublicKeyTag = "PublicKey";
        private const string TypeTag = "type";
        private const string UrnPrefix = "urn:oid:";
        private const string UrnTag = "URN";
        private const string ValueTag = "Value";
        private const string XsiPrefix = "xsi";
        private const string XmlnsPrefix = "xmlns";
        private const string XTag = "X";
        private const string YTag = "Y";

        internal static ECParameters FromXml(string xmlString, int keyLength)
        {
            using var textReader = new StringReader(xmlString);
            using var reader = XmlReader.Create(textReader);
            if (!reader.IsStartElement(ECDsaKeyValueTag, Namespace))
                throw new ArgumentException(CryptographyStrings.CryptographicMissingECDsaKeyValue, nameof(xmlString));
            reader.ReadStartElement();

            if (!reader.IsStartElement(DomainParametersTag, Namespace))
                throw new ArgumentException(CryptographyStrings.CryptographicMissingDomainParameters, nameof(xmlString));
            var curve = ReadDomainParameters(reader, keyLength);

            if (!reader.IsStartElement(PublicKeyTag, Namespace))
                throw new ArgumentException(CryptographyStrings.CryptographicMissingPublicKey, nameof(xmlString));
            var publicKey = ReadECPoint(reader, PublicKeyTag, Namespace, keyLength);

            reader.ReadEndElement();

            return new ECParameters { Curve = curve, Q = publicKey };
        }

        private static ECCurve ReadDomainParameters(XmlReader reader, int keyLength)
        {
            reader.ReadStartElement();

            ECCurve result;
            if (reader.IsStartElement(ExplicitParamsTag, Namespace))
                result = ReadExplicitParameters(reader, keyLength);
            else if (reader.IsStartElement(NamedCurveTag, Namespace))
                result = ReadNamedCurveParameters(reader);
            else throw new ArgumentException(CryptographyStrings.CryptographicMissingDomainParameters, nameof(reader));

            reader.ReadEndElement();

            return result;
        }

        private static ECCurve ReadNamedCurveParameters(XmlReader reader)
        {
            var isEmpty = reader.IsEmptyElement;

            if (!reader.MoveToAttribute(UrnTag))
                throw new NotImplementedException();
            reader.ReadAttributeValue();
            var urn = reader[UrnTag];
            if (!urn.StartsWith(UrnPrefix, StringComparison.Ordinal))
                throw new NotImplementedException();
            var oidValue = urn.Substring(UrnPrefix.Length);
            reader.MoveToElement();
            reader.ReadStartElement(NamedCurveTag, Namespace);
            if (!isEmpty)
                reader.ReadEndElement();
            return ECCurve.CreateFromValue(oidValue);
        }

        private static ECCurve ReadExplicitParameters(XmlReader reader, int keyLength)
        {
            reader.ReadStartElement(ExplicitParamsTag, Namespace);
            reader.MoveToContent();
            var prime = ReadPrimeFieldParameters(reader, FieldParamsTag, Namespace, keyLength);
            reader.MoveToContent();
            reader.ReadStartElement(CurveParamsTag, Namespace);
            reader.MoveToContent();
            var a = ReadPrimeFieldElement(reader, ATag, Namespace, keyLength);
            reader.MoveToContent();
            var b = ReadPrimeFieldElement(reader, BTag, Namespace, keyLength);
            reader.ReadEndElement();
            reader.MoveToContent();
            reader.ReadStartElement(BasePointParamsTag, Namespace);
            reader.MoveToContent();
            var baseBoint = ReadECPoint(reader, BasePointTag, Namespace, keyLength);
            reader.MoveToContent();
            var order = CryptoUtils.ToNormalizedByteArray(BigInteger.Parse(reader.ReadElementContentAsString(OrderTag, Namespace), CultureInfo.InvariantCulture), keyLength);
            byte[]? cofactor;
            if (reader.IsStartElement(CofactorTag, Namespace))
                cofactor = CryptoUtils.ToNormalizedByteArray(BigInteger.Parse(reader.ReadElementContentAsString(), CultureInfo.InvariantCulture), keyLength);
            else cofactor = null;
            reader.ReadEndElement();
            reader.ReadEndElement();

            return new ECCurve
            {
                CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
                Prime = prime,
                A = a,
                B = b,
                G = baseBoint,
                Order = order,
                Cofactor = cofactor,
            };
        }

        private static byte[] ReadPrimeFieldParameters(XmlReader reader, string localName, string ns, int keyLength)
        {
            reader.ReadStartElement(localName, ns);
            reader.MoveToContent();
            var value = CryptoUtils.ToNormalizedByteArray(BigInteger.Parse(reader.ReadElementContentAsString(PTag, Namespace), CultureInfo.InvariantCulture), keyLength);
            reader.ReadEndElement();
            return value;
        }

        private static byte[] ReadPrimeFieldElement(XmlReader reader, string localName, string ns, int keyLength)
        {
            var isEmpty = reader.IsEmptyElement;
            if (!reader.MoveToAttribute(TypeTag, XmlSchema.InstanceNamespace))
                throw new NotImplementedException();
            reader.ReadAttributeValue();
            var xsiType = reader.Value;
            if (xsiType != PrimeFieldElemTypeValue)
                throw new NotImplementedException();
            if (!reader.MoveToAttribute(ValueTag))
                throw new NotImplementedException();
            reader.ReadAttributeValue();
            var result = CryptoUtils.ToNormalizedByteArray(BigInteger.Parse(reader[ValueTag], CultureInfo.InvariantCulture), keyLength);
            reader.MoveToElement();
            reader.ReadStartElement(localName, ns);
            if (!isEmpty)
                reader.ReadEndElement();
            return result;
        }

        private static ECPoint ReadECPoint(XmlReader reader, string localName, string ns, int keyLength)
        {
            reader.ReadStartElement(localName, ns);
            reader.MoveToContent();
            var x = ReadPrimeFieldElement(reader, XTag, Namespace, keyLength);
            reader.MoveToContent();
            var y = ReadPrimeFieldElement(reader, YTag, Namespace, keyLength);
            reader.ReadEndElement();
            return new ECPoint
            {
                X = x,
                Y = y
            };
        }

        internal static string ToXmlString(ECParameters parameters)
        {
            var xml = new StringBuilder();
            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
#if DEBUG
                Indent = true,
                IndentChars = "  ",
#endif
            };

            using (var writer = XmlWriter.Create(xml, settings))
            {
                writer.WriteStartElement(ECDsaKeyValueTag, Namespace);
                writer.WriteAttributeString(null, XmlnsPrefix, null, Namespace);
                writer.WriteAttributeString(XmlnsPrefix, XsiPrefix, null, XmlSchema.InstanceNamespace);
                WriteDomainParameters(writer, parameters.Curve);
                WriteECPoint(writer, PublicKeyTag, Namespace, parameters.Q);
                writer.WriteEndElement();
            }

            return xml.ToString();
        }

        private static void WriteDomainParameters(XmlWriter writer, ECCurve curve)
        {
            writer.WriteStartElement(DomainParametersTag, Namespace);

            switch (curve.CurveType)
            {
                case ECCurve.ECCurveType.PrimeShortWeierstrass:
                    WriteExplicitParameters(writer, curve);
                    break;

                case ECCurve.ECCurveType.Named:
                    WriteNamedCurveParameters(writer, curve.Oid);
                    break;

                default:
                    throw new NotImplementedException();
            }

            writer.WriteEndElement();
        }

        private static void WriteNamedCurveParameters(XmlWriter writer, Oid oid)
        {
            writer.WriteStartElement(NamedCurveTag, Namespace);
            writer.WriteAttributeString(UrnTag, UrnPrefix + oid.Value);
            writer.WriteEndElement();
        }

        private static void WriteExplicitParameters(XmlWriter writer, ECCurve curve)
        {
            writer.WriteStartElement(ExplicitParamsTag, Namespace);
            WritePrimeFieldParameters(writer, curve.Prime);
            WriteCurveParameters(writer, curve);
            WriteBasePointParameters(writer, curve);
            writer.WriteEndElement();
        }

        private static void WritePrimeFieldParameters(XmlWriter writer, byte[] prime)
        {
            writer.WriteStartElement(FieldParamsTag, Namespace);
            WriteXsiType(writer, PrimeFieldParamsTypeValue, Namespace);
            writer.WriteElementString(PTag, Namespace, ToNonNegativeNumericString(prime));
            writer.WriteEndElement();
        }

        private static void WriteCurveParameters(XmlWriter writer, ECCurve curve)
        {
            writer.WriteStartElement(CurveParamsTag, Namespace);
            WritePrimeFieldElement(writer, ATag, Namespace, curve.A);
            WritePrimeFieldElement(writer, BTag, Namespace, curve.B);
            writer.WriteEndElement();
        }

        private static void WriteBasePointParameters(XmlWriter writer, ECCurve curve)
        {
            writer.WriteStartElement(BasePointParamsTag, Namespace);
            WriteECPoint(writer, BasePointTag, Namespace, curve.G);
            writer.WriteElementString(OrderTag, Namespace, ToNonNegativeNumericString(curve.Order));
            if (curve.Cofactor != null)
                writer.WriteElementString(CofactorTag, Namespace, ToNonNegativeNumericString(curve.Cofactor));
            writer.WriteEndElement();
        }

        private static void WriteECPoint(XmlWriter writer, string localName, string ns, ECPoint point)
        {
            writer.WriteStartElement(localName, ns);
            WritePrimeFieldElement(writer, XTag, Namespace, point.X);
            WritePrimeFieldElement(writer, YTag, Namespace, point.Y);
            writer.WriteEndElement();
        }

        private static void WritePrimeFieldElement(XmlWriter writer, string localName, string ns, byte[] value)
        {
            writer.WriteStartElement(localName, ns);
            WriteXsiType(writer, PrimeFieldElemTypeValue, Namespace);
            writer.WriteAttributeString(ValueTag, ToNonNegativeNumericString(value));
            writer.WriteEndElement();
        }

        private static void WriteXsiType(XmlWriter writer, string localName, string ns)
        {
            writer.WriteStartAttribute(TypeTag, XmlSchema.InstanceNamespace);
            writer.WriteQualifiedName(localName, ns);
            writer.WriteEndAttribute();
        }

        private static string ToNonNegativeNumericString(byte[] value)
        {
            var numericValue = new BigInteger(value);
            if (numericValue < BigInteger.Zero)
                numericValue += (BigInteger.One << value.Length * 8);
            return numericValue.ToString("R", CultureInfo.InvariantCulture);
        }
    }
}
