using System.IO;
using System.Reflection;
using System.Xml;

namespace OpenGost.Security.Cryptography;

internal static class ResourceUtils
{
    private static XmlReaderSettings Settings { get; } = new XmlReaderSettings
    {
        CheckCharacters = false,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true,
    };

    internal static XmlReader GetXmlResource(string resourceName)
        => XmlReader.Create(GetResourceStream(resourceName), Settings, resourceName);

    internal static byte[] GetBinaryResource(string resourceName)
    {
        using var memoryStream = new MemoryStream();
        using (var resourceStream = GetResourceStream(resourceName, Assembly.GetExecutingAssembly()))
            resourceStream.CopyTo(memoryStream);

        return memoryStream.ToArray();
    }

    private static Stream GetResourceStream(string resourceName)
        => GetResourceStream(resourceName, Assembly.GetExecutingAssembly());

    private static Stream GetResourceStream(string resourceName, Assembly assembly)
       => assembly.GetManifestResourceStream(resourceName)!;
}
