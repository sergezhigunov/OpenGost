using System.Reflection;
using System.Xml;

namespace OpenGost.Security.Cryptography.Tests;

internal static class ResourceUtils
{
    public static XmlDocument GetXmlDocument(string fileName)
    {
        var document = new XmlDocument
        {
            PreserveWhitespace = true,
        };
        using var stream = GetResourceStream(fileName);
        using var reader = XmlReader.Create(stream);
        document.Load(reader);
        return document;
    }

    public static byte[] GetBinary(string fileName)
    {
        using var memoryStream = new MemoryStream();
        using (var resourceStream = GetResourceStream(fileName))
            resourceStream.CopyTo(memoryStream);

        return memoryStream.ToArray();
    }

    private static Stream GetResourceStream(string fileName)
       => Assembly.GetExecutingAssembly()
        .GetManifestResourceStream($"OpenGost.Security.Cryptography.Tests.Resources.{fileName}")!;
}
