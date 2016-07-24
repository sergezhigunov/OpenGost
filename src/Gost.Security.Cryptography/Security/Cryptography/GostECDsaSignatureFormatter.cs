using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Creates a <see cref="GostECDsa"/> signature.
    /// </summary>
    [ComVisible(true)]
    public class GostECDsaSignatureFormatter : AsymmetricSignatureFormatter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaSignatureFormatter"/> class.
        /// </summary>
        public GostECDsaSignatureFormatter()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaSignatureFormatter"/> class with the specified key.
        /// </summary>
        /// <param name="key">
        /// The instance of <see cref="GostECDsa"/> that holds the key.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key"/> is <c>null</c>.
        /// </exception>
        public GostECDsaSignatureFormatter(AsymmetricAlgorithm key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates the <see cref="GostECDsa"/> signature for the specified data.
        /// </summary>
        /// <param name="rgbHash">
        /// The data to be signed.
        /// </param>
        /// <returns>
        /// The digital signature for the specified data.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="rgbHash"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// The OID is <c>null</c>.
        /// -or-
        /// The <see cref="GostECDsa"/> key is <c>null</c>.
        /// </exception>
        public override byte[] CreateSignature(byte[] rgbHash)
        {
            if (rgbHash == null) throw new ArgumentNullException(nameof(rgbHash));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Specifies the hash algorithm for the <see cref="GostECDsa"/> signature formatter.
        /// </summary>
        /// <param name="strName">
        /// The name of the hash algorithm to use for the signature formatter. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="strName"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// The <paramref name="strName"/> parameter does not map to the hash algorithm.
        /// </exception>
        public override void SetHashAlgorithm(string strName)
        {
            if (strName == null) throw new ArgumentNullException(nameof(strName));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Specifies the key to be used for the <see cref="GostECDsa"/> signature formatter.
        /// </summary>
        /// <param name="key">
        /// The instance of <see cref="GostECDsa"/> that holds the key. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key"/> is <c>null</c>.
        /// </exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            throw new NotImplementedException();
        }
    }
}
