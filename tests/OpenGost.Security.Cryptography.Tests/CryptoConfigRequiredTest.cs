using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Xml.XPath;

namespace OpenGost.Security.Cryptography
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
            var mscorlibVersion = typeof(CryptoConfig).Assembly.GetName().Version.ToString();

            using (var reader = ResourceUtils.GetXmlResource("OpenGost.Security.Cryptography.Tests.Crypto.config"))
            {
                var document = new XPathDocument(reader);
                var navigator = document.CreateNavigator();
                var mscorlibIterator = navigator.Select("configuration/mscorlib");
                XPathNavigator mscorlib = null;
                while (mscorlibIterator.MoveNext())
                {
                    var versionSpecificMscorlib = false;
                    var current = mscorlibIterator.Current;
                    var versionAttributeIterator = current.Select("@version");
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

                var cryptographySettings = mscorlib.SelectSingleNode("cryptographySettings");

                if (cryptographySettings == null)
                    return;

                var cryptoNameMapping = cryptographySettings.SelectSingleNode("cryptoNameMapping");
                if (cryptoNameMapping != null)
                    ConfigureCryptoNameMapping(cryptoNameMapping);

                var oidMap = cryptographySettings.SelectSingleNode("oidMap");
                if (oidMap != null)
                    ConfigureOidMap(oidMap);
            }
        }

        private static void ConfigureCryptoNameMapping(XPathNavigator cryptoNameMapping)
        {
            var nameMappings = new Dictionary<string, string>();
            var typeAliases = new Dictionary<string, string>();

            var cryptoClasses = cryptoNameMapping.SelectSingleNode("cryptoClasses");
            if (cryptoClasses != null)
            {
                var cryptoClassIterator = cryptoClasses.Select("cryptoClass");
                while (cryptoClassIterator.MoveNext())
                {
                    var cryptoClass = cryptoClassIterator.Current;
                    if (cryptoClass.MoveToFirstAttribute())
                        typeAliases.Add(cryptoClass.Name, cryptoClass.Value);
                }
            }

            var nameEntryIterator = cryptoNameMapping.Select("nameEntry");
            while (nameEntryIterator.MoveNext())
            {
                var nameEntry = nameEntryIterator.Current;
                var friendlyName = nameEntry.SelectSingleNode("@name")?.Value;
                var className = nameEntry.SelectSingleNode("@class")?.Value;
                if (friendlyName != null && className != null)
                    if (typeAliases.ContainsKey(className))
                        nameMappings.Add(friendlyName, typeAliases[className]);
            }

            foreach (var item in nameMappings)
            {
                var algorithm = Type.GetType(item.Value, false, false);
                if (algorithm != null)
                    CryptoConfig.AddAlgorithm(algorithm, item.Key);
            }
        }

        private static void ConfigureOidMap(XPathNavigator oidMap)
        {
            var oidMapings = new Dictionary<string, string>();
            var oidEntryIterator = oidMap.Select("oidEntry");
            while (oidEntryIterator.MoveNext())
            {
                var oidEntry = oidEntryIterator.Current;
                var oidString = oidEntry.SelectSingleNode("@OID")?.Value;
                var friendlyName = oidEntry.SelectSingleNode("@name")?.Value;

                if ((friendlyName != null) && (oidString != null))
                    oidMapings.Add(friendlyName, oidString);
            }

            foreach (var item in oidMapings)
                CryptoConfig.AddOID(item.Value, item.Key);
        }
    }
}
