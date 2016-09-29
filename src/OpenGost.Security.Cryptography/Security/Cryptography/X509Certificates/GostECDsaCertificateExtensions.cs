using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenGost.Security.Cryptography.X509Certificates
{
    using static AsnUtils;
    using static CryptoConstants;
    using static CryptoUtils;
    using static ECCurveOidMap;

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
        /// The public key, or <c>null</c> if the certificate does not have a
        /// <see cref="GostECDsa"/> public key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="certificate"/> parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The handle is invalid.
        /// </exception>
        public static GostECDsa GetECDsaPublicKey(this X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            if (!IsGostECDsa(certificate))
                return null;

            PublicKey publicKey = certificate.PublicKey;

            GostECDsa result;
            switch (publicKey.EncodedKeyValue.Oid.Value)
            {
                case GostECDsa256OidValue:
                    result = GostECDsa256.Create();
                    break;

                case GostECDsa512OidValue:
                    result = GostECDsa512.Create();
                    break;

                default:
                    return null;
            }

            try
            {
                ECParameters parameters = ReadParameters(publicKey);
                result.ImportParameters(parameters);
            }
            catch
            {
                result.Dispose();
                throw;
            }

            return result;
        }

        private static ECParameters ReadParameters(PublicKey publicKey)
        {
            byte[] publicKeyValue = DecodeOctetString(publicKey.EncodedKeyValue);
            int keySize = publicKeyValue.Length / 2;
            var publicPoint = new ECPoint
            {
                X = publicKeyValue.Subarray(0, keySize),
                Y = publicKeyValue.Subarray(keySize),
            };

            EraseData(ref publicKeyValue);

            ECCurve curve = default(ECCurve);

            foreach (AsnEncodedData item in DecodeSequence(publicKey.EncodedParameters))
            {
                AsnTag tag = GetAsnTag(item);
                if (tag == AsnTag.ObjectIdentifier)
                {
                    string oidValue = DecodeOidValue(item);
                    if (OidValueRegistered(oidValue))
                    {
                        curve = ECCurve.CreateFromValue(oidValue);
                        continue;
                    }
                    else if (oidValue == Streebog256OidValue || oidValue == Streebog512OidValue)
                        continue;
                    else
                        throw new NotImplementedException();
                }
                else
                    throw new NotImplementedException();
            }

            return new ECParameters { Curve = curve, Q = publicPoint };
        }

        /// <summary>
        /// Gets the <see cref="GostECDsa"/> private key from the <see cref="X509Certificate2"/>
        /// certificate.
        /// </summary>
        /// <param name="certificate">
        /// The certificate.
        /// </param>
        /// <returns>
        /// The private key, or <c>null</c> if the certificate does not have a
        /// <see cref="GostECDsa"/> private key.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="certificate"/> parameter is <c>null</c>.
        /// </exception>
        public static GostECDsa GetECDsaPrivateKey(this X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            if (!certificate.HasPrivateKey || !IsGostECDsa(certificate))
                return null;

            throw new NotImplementedException();
        }

        private static bool IsGostECDsa(X509Certificate2 certificate)
        {
            string value = certificate.PublicKey.Oid.Value;
            if (value != GostECDsa256OidValue && value != GostECDsa512OidValue)
                return false;

            foreach (X509Extension extension in certificate.Extensions)
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
    }
}
