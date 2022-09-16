namespace OpenGost.Security.Cryptography;

/// <summary>
/// Specifies the GOST XML Digital Signature constants.
/// </summary>
public static class OpenGostSignedXml
{
    private const string MethodPrefix = "urn:ietf:params:xml:ns:cpxmlsec:algorithms";
    private const string GostECDsaMethod = "gostr34102012";
    private const string StreebogMethod = "gostr34112012";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the <see cref="GostECDsa"/> <see cref="Streebog256"/>
    /// signature method variation for XML digital signatures.
    /// </summary>
    public const string XmlDsigGostECDsaStreebog256Url = $"{MethodPrefix}:{GostECDsaMethod}-{StreebogMethod}-256";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the <see cref="GostECDsa"/> <see cref="Streebog512"/>
    /// signature method variation for XML digital signatures.
    /// </summary>
    public const string XmlDsigGostECDsaStreebog512Url = $"{MethodPrefix}:{GostECDsaMethod}-{StreebogMethod}-512";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the standard <see cref="Streebog256"/> digest method
    /// for XML digital signatures.
    /// </summary>
    public const string XmlDsigStreebog256Url = $"{MethodPrefix}:{StreebogMethod}-256";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the standard <see cref="Streebog512"/> digest method
    /// for XML digital signatures.
    /// </summary>
    public const string XmlDsigStreebog512Url = $"{MethodPrefix}:{StreebogMethod}-512";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the standard <see cref="HMACStreebog256"/> digest method
    /// for XML digital signatures.
    /// </summary>
    public const string XmlDsigHMACStreebog256Url = $"{MethodPrefix}:hmac-{StreebogMethod}-256";

    /// <summary>
    /// Represents the Uniform Resource Identifier (URI) for the standard <see cref="HMACStreebog512"/> digest method
    /// for XML digital signatures.
    /// </summary>
    public const string XmlDsigHMACStreebog512Url = $"{MethodPrefix}:hmac-{StreebogMethod}-512";
}
