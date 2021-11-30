using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace OpenGost.Security.Cryptography;

[ExcludeFromCodeCoverage]
public abstract class CryptoConfigRequiredTest
{
    static CryptoConfigRequiredTest() => ConfigureCryptography();

    private static void ConfigureCryptography()
    {
        XDocument document;
        using (var reader = ResourceUtils.GetXmlResource("OpenGost.Security.Cryptography.Crypto.config"))
            document = XDocument.Load(reader, LoadOptions.None);

        var cryptographySettings = document
            .Element(XName.Get("configuration"))?
            .Element(XName.Get("mscorlib"))?
            .Element(XName.Get("cryptographySettings"));

        if (cryptographySettings == null)
            return;

        var cryptoNameMapping = cryptographySettings.Element(XName.Get("cryptoNameMapping"));
        if (cryptoNameMapping != null)
            ConfigureCryptoNameMapping(cryptoNameMapping);

        var oidMap = cryptographySettings.Element(XName.Get("oidMap"));
        if (oidMap != null)
            ConfigureOidMap(oidMap);
    }

    private static void ConfigureCryptoNameMapping(XElement cryptoNameMapping)
    {
        var typeAliases = (
            from cryptoClass in cryptoNameMapping
                .Elements(XName.Get("cryptoClasses"))
                .Elements(XName.Get("cryptoClass"))
            let attribute = cryptoClass.Attributes().FirstOrDefault()
            where attribute?.Value != null
            let type = Type.GetType(attribute.Value, false, false)
            where type != null
            select (Key: attribute.Name.LocalName, Value: type))
            .ToDictionary(x => x.Key, x => x.Value);

        var nameMappings =
            from nameEntry in cryptoNameMapping.Elements(XName.Get("nameEntry"))
            let friendlyName = nameEntry.Attribute(XName.Get("name"))?.Value
            let className = nameEntry.Attribute(XName.Get("class"))?.Value
            where friendlyName != null && className != null
            let type = typeAliases.TryGetValue(className, out var value) ? value : null
            where type != null
            group friendlyName by type into items
            select items;

        foreach (var items in nameMappings)
            CryptoConfig.AddAlgorithm(items.Key, items.ToArray());
    }

    private static void ConfigureOidMap(XElement oidMap)
    {
        var oidMapings =
            from oidEntry in oidMap.Elements(XName.Get("oidEntry"))
            let oid = oidEntry.Attribute(XName.Get("OID"))?.Value
            let name = oidEntry.Attribute(XName.Get("name"))?.Value
            where name != null && oid != null
            group name by oid into items
            select items;

        foreach (var items in oidMapings)
            CryptoConfig.AddOID(items.Key, items.ToArray());
    }
}
