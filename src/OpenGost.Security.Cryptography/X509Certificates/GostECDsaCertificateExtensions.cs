using System;
using System.Formats.Asn1;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides extension methods for retrieving <see cref="GostECDsa"/> implementations for the
    /// public and private keys of a <see cref="X509Certificate2"/> certificate.
    /// </summary>
    public static class GostECDsaCertificateExtensions
    {
        /// <summary>
        /// Gets the <see cref="GostECDsa"/> public key from the <see cref="X509Certificate2"/>
        /// certificate.
        /// </summary>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// The public key, or <see langword="null"/> if the certificate does not have a
        /// <see cref="GostECDsa"/> public key.
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
                CryptoConstants.GostECDsa256OidValue => GostECDsa256.Create(),
                CryptoConstants.GostECDsa512OidValue => GostECDsa512.Create(),
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

        /// <summary>
        /// Gets the <see cref="GostECDsa"/> private key from the <see cref="X509Certificate2"/>
        /// certificate.
        /// </summary>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// The private key, or <see langword="null"/> if the certificate does not have a
        /// <see cref="GostECDsa"/> private key.
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

        private static bool IsGostECDsa(X509Certificate2 certificate)
        {
            var value = certificate.PublicKey.Oid.Value;
            if (value != CryptoConstants.GostECDsa256OidValue && value != CryptoConstants.GostECDsa512OidValue)
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
            var keySource = new ReadOnlySpan<byte>(publicKey.EncodedKeyValue.RawData);
            var publicKeyValue = AsnDecoder.ReadOctetString(keySource, AsnEncodingRules.BER, out _);
            var keySize = publicKeyValue.Length / 2;
            var publicPoint = new ECPoint
            {
                X = publicKeyValue.Subarray(0, keySize),
                Y = publicKeyValue.Subarray(keySize),
            };

            CryptoUtils.EraseData(ref publicKeyValue);

            var parametersSource = new ReadOnlyMemory<byte>(publicKey.EncodedParameters.RawData);
            var reader = new AsnReader(parametersSource, AsnEncodingRules.BER);
            reader = reader.ReadSequence();
            var curve = default(ECCurve);

            while (reader.HasData)
            {
                var tag = reader.PeekTag();
                if (tag == Asn1Tag.ObjectIdentifier)
                {
                    var oidValue = reader.ReadObjectIdentifier();
                    if (ECCurveOidMap.OidValueRegistered(oidValue))
                    {
                        curve = ECCurve.CreateFromValue(oidValue);
                        continue;
                    }
                    else if (oidValue == CryptoConstants.Streebog256OidValue || oidValue == CryptoConstants.Streebog512OidValue)
                        continue;
                    else
                        throw new NotImplementedException();
                }
                else
                    throw new NotImplementedException();
            }

            return new ECParameters { Curve = curve, Q = publicPoint };
        }
    }
}
