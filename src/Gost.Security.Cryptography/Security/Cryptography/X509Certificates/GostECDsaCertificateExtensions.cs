using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Gost.Security.Cryptography.X509Certificates
{
    using static CryptoConstants;

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

            throw new NotImplementedException();
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
            string algName = certificate.PublicKey.Oid.FriendlyName;
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
