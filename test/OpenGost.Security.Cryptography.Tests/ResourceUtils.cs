using System.IO;
using System.Reflection;
using System.Xml;

namespace OpenGost.Security.Cryptography
{
    internal static class ResourceUtils
    {
        internal static XmlReader GetXmlResource(string resourceName)
            => XmlReader.Create(GetResourceStream(resourceName));

        internal static byte[] GetBinaryResource(string resourceName)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
#if NET45
                using (Stream resourceStream = GetResourceStream(resourceName, Assembly.GetExecutingAssembly()))
#elif NETCOREAPP1_0
                using (Stream resourceStream = GetResourceStream(resourceName, typeof(ResourceUtils).GetTypeInfo().Assembly))
#endif
                    resourceStream.CopyTo(memoryStream);

                return memoryStream.ToArray();
            }
        }

        private static Stream GetResourceStream(string resourceName)
#if NET45
            => GetResourceStream(resourceName, Assembly.GetExecutingAssembly());
#elif NETCOREAPP1_0
            => GetResourceStream(resourceName, typeof(ResourceUtils).GetTypeInfo().Assembly);
#endif

        private static Stream GetResourceStream(string resourceName, Assembly assembly)
           => assembly.GetManifestResourceStream(resourceName);
    }
}
