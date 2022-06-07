using System.Formats.Asn1;
using OpenGost.Security.Cryptography;
using OpenGost.Security.Cryptography.Asn1;
using OpenGost.Security.Cryptography.Properties;

namespace System.Security.Cryptography.X509Certificates;

using static CryptoConstants;

/// <summary>
/// Provides extension methods for retrieving GOST 34.10-2018 <see cref="ECDsa"/> implementations for the
/// public and private keys of a <see cref="X509Certificate2"/> certificate.
/// </summary>
public static class GostECDsaCertificateExtensions
{
    /// <summary>
    /// Gets the GOST 34.10-2018 <see cref="GostECDsa"/> public key from the <see cref="X509Certificate2"/>
    /// certificate.
    /// </summary>
    /// <param name="certificate">
    /// The certificate.
    /// </param>
    /// <returns>
    /// The public key, or <see langword="null"/> if the certificate does not have a
    /// GOST 34.10-2018 <see cref="GostECDsa"/> public key.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="certificate"/> parameter is <see langword="null"/>.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The handle is invalid.
    /// </exception>
    public static GostECDsa? GetGostECDsaPublicKey(this X509Certificate2 certificate)
    {
        if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));

        if (!IsGostECDsa(certificate))
            return null;

        var publicKey = certificate.PublicKey;
        GostECDsa? result = publicKey.EncodedKeyValue.Oid.Value switch
        {
            GostECDsa256OidValue or GostECDsa512OidValue => GostECDsa.Create(),
            _ => null
        };
        if (result is not null)
        {
            try
            {
                var parameters = ReadParameters(publicKey);
                result.ImportParameters(parameters);
            }
            catch
            {
                result.Dispose();
                throw;
            }
        }
        return result;
    }

    /*
    /// <summary>
    /// Gets the GOST 34.10-2018 <see cref="GostECDsa"/> private key from the <see cref="X509Certificate2"/>
    /// certificate.
    /// </summary>
    /// <param name="certificate">
    /// The certificate.
    /// </param>
    /// <returns>
    /// The private key, or <see langword="null"/> if the certificate does not have a
    /// GOST 34.10-2018 <see cref="GostECDsa"/> private key.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// The <paramref name="certificate"/> parameter is <see langword="null"/>.
    /// </exception>
    public static GostECDsa? GetGostECDsaPrivateKey(this X509Certificate2 certificate)
    {
        if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));

        if (!certificate.HasPrivateKey || !IsGostECDsa(certificate))
            return null;

        throw new NotImplementedException();
    }
    */

    private static bool IsGostECDsa(X509Certificate2 certificate)
    {
        var value = certificate.PublicKey.Oid.Value;
        if (value != GostECDsa256OidValue && value != GostECDsa512OidValue)
            return false;

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid.Value == "2.5.29.15")
            {
                var ext = (X509KeyUsageExtension)extension;

                if (!(ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement)))
                {
                    return true;
                }
                if (ext.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) ||
                    ext.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation) ||
                    ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) ||
                    ext.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
                    return true;
                else
                    return false;
            }
        }
        return true;
    }

    [SecuritySafeCritical]
    private static ECParameters ReadParameters(PublicKey publicKey)
    {
        var curve = ReadCurve(publicKey.EncodedParameters.RawData);
        var publicPoint = ReadPublicKey(publicKey.EncodedKeyValue.RawData);
        return new ECParameters { Curve = curve, Q = publicPoint };
    }

    [SecuritySafeCritical]
    private static ECPoint ReadPublicKey(ReadOnlyMemory<byte> encodedKeyValue)
    {
        var reader = new AsnValueReader(encodedKeyValue.Span, AsnEncodingRules.BER);
        if (reader.TryReadPrimitiveOctetString(out var publicKeyValue))
        {
            var keySize = publicKeyValue.Length / 2;
            var publicPoint = new ECPoint
            {
                X = publicKeyValue.Slice(0, keySize).ToArray(),
                Y = publicKeyValue.Slice(keySize, keySize).ToArray(),
            };
            reader.ThrowIfNotEmpty();
            return publicPoint;
        }
        throw new CryptographicException(CryptographyStrings.CryptographicDerInvalidEncoding);
    }

    [SecuritySafeCritical]
    private static ECCurve ReadCurve(ReadOnlyMemory<byte> encodedParameters)
    {
        var parameters = GostECDsaPublicKeyParameters.Decode(encodedParameters, AsnEncodingRules.BER);
        var algorithm = parameters.PublicKeyParamSet;
        if (ECCurveOidMap.OidValueRegistered(algorithm))
            return ECCurve.CreateFromValue(algorithm);
        throw new CryptographicException(CryptographyStrings.CryptographicUnknownOid(algorithm));
    }
}
