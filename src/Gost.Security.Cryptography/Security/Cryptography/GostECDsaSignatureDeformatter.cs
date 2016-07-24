using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Verifies a <see cref="GostECDsa"/> signature.
    /// </summary>
    [ComVisible(true)]
    public class GostECDsaSignatureDeformatter : AsymmetricSignatureDeformatter
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaSignatureDeformatter"/> class.
        /// </summary>
        public GostECDsaSignatureDeformatter()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsaSignatureDeformatter"/> class with the specified key.
        /// </summary>
        /// <param name="key">
        /// The instance of <see cref="GostECDsa"/> that holds the key.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key"/> is <c>null</c>.
        /// </exception>
        public GostECDsaSignatureDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));

            throw new NotImplementedException();
        }

        /// <summary>
        /// Specifies the hash algorithm for the <see cref="GostECDsa"/> signature deformatter.
        /// </summary>
        /// <param name="strName">
        /// The name of the hash algorithm to use for the signature deformatter. 
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
        /// Specifies the key to be used for the <see cref="GostECDsa"/> signature deformatter.
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

        /// <summary>
        /// Verifies the <see cref="GostECDsa"/> signature on the data.
        /// </summary>
        /// <param name="rgbHash">
        /// The data signed with <paramref name="rgbSignature"/>.
        /// </param>
        /// <param name="rgbSignature">
        /// The signature to be verified for <paramref name="rgbHash"/>. 
        /// </param>
        /// <returns>
        /// <c>true</c> if the signature is valid for the data;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="rgbHash"/> is <c>null</c>.
        /// -or-
        /// <paramref name="rgbSignature"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// The <see cref="GostECDsa"/> key is missing.
        /// </exception>
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            if (rgbHash == null) throw new ArgumentNullException(nameof(rgbHash));
            if (rgbSignature == null) throw new ArgumentNullException(nameof(rgbSignature));

            throw new NotImplementedException();
        }
    }
}
