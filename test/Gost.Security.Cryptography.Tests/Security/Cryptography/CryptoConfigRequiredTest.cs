using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.XPath;
using Gost.Properties;

namespace Gost.Security.Cryptography
{
    [ExcludeFromCodeCoverage]
    public abstract class CryptoConfigRequiredTest
    {
        static CryptoConfigRequiredTest()
        {
            ConfigureCryptography();
        }

        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        private static void ConfigureCryptography()
        {
            string mscorlibVersion = typeof(CryptoConfig).Assembly.GetName().Version.ToString();

            using (var stream = new MemoryStream(Resources.CryptoConfig))
            using (XmlReader reader = XmlReader.Create(stream))
            {
                var document = new XPathDocument(reader);
                XPathNavigator navigator = document.CreateNavigator();
                XPathNodeIterator mscorlibIterator = navigator.Select("configuration/mscorlib");
                XPathNavigator mscorlib = null;
                while (mscorlibIterator.MoveNext())
                {
                    bool versionSpecificMscorlib = false;
                    XPathNavigator current = mscorlibIterator.Current;
                    XPathNodeIterator versionAttributeIterator = current.Select("@version");
                    while (versionAttributeIterator.MoveNext())
                    {
                        versionSpecificMscorlib = true;

                        if (mscorlibVersion == versionAttributeIterator.Current.Value)
                        {
                            mscorlib = current;
                            break;
                        }
                    }

                    if (!versionSpecificMscorlib)
                        mscorlib = current;

                    if (mscorlib != null)
                        break;
                }

                if (mscorlib == null)
                    return;

                XPathNavigator cryptographySettings = mscorlib.SelectSingleNode("cryptographySettings");

                if (cryptographySettings == null)
                    return;

                XPathNavigator cryptoNameMapping = cryptographySettings.SelectSingleNode("cryptoNameMapping");
                if (cryptoNameMapping != null)
                    ConfigureCryptoNameMapping(cryptoNameMapping);

                XPathNavigator oidMap = cryptographySettings.SelectSingleNode("oidMap");
                if (oidMap != null)
                    ConfigureOidMap(oidMap);
            }
        }

        private static void ConfigureCryptoNameMapping(XPathNavigator cryptoNameMapping)
        {
            Dictionary<string, string> nameMappings = new Dictionary<string, string>();
            Dictionary<string, string> typeAliases = new Dictionary<string, string>();

            XPathNavigator cryptoClasses = cryptoNameMapping.SelectSingleNode("cryptoClasses");
            if (cryptoClasses != null)
            {
                XPathNodeIterator cryptoClassIterator = cryptoClasses.Select("cryptoClass");
                while (cryptoClassIterator.MoveNext())
                {
                    XPathNavigator cryptoClass = cryptoClassIterator.Current;
                    if (cryptoClass.MoveToFirstAttribute())
                        typeAliases.Add(cryptoClass.Name, cryptoClass.Value);
                }
            }

            XPathNodeIterator nameEntryIterator = cryptoNameMapping.Select("nameEntry");
            while (nameEntryIterator.MoveNext())
            {
                XPathNavigator nameEntry = nameEntryIterator.Current;
                string friendlyName = nameEntry.SelectSingleNode("@name")?.Value;
                string className = nameEntry.SelectSingleNode("@class")?.Value;
                if (friendlyName != null && className != null)
                    if (typeAliases.ContainsKey(className))
                        nameMappings.Add(friendlyName, typeAliases[className]);
            }

            foreach (var item in nameMappings)
            {
                Type algorithm = Type.GetType(item.Value, false, false);
                if (algorithm != null)
                    CryptoConfig.AddAlgorithm(algorithm, item.Key);
            }
        }

        private static void ConfigureOidMap(XPathNavigator oidMap)
        {
            Dictionary<string, string> oidMapings = new Dictionary<string, string>();
            XPathNodeIterator oidEntryIterator = oidMap.Select("oidEntry");
            while (oidEntryIterator.MoveNext())
            {
                XPathNavigator oidEntry = oidEntryIterator.Current;
                string oidString = oidEntry.SelectSingleNode("@OID")?.Value;
                string friendlyName = oidEntry.SelectSingleNode("@name")?.Value;

                if ((friendlyName != null) && (oidString != null))
                    oidMapings.Add(friendlyName, oidString);
            }

            foreach (var item in oidMapings)
                CryptoConfig.AddOID(item.Value, item.Key);
        }
    }
}
