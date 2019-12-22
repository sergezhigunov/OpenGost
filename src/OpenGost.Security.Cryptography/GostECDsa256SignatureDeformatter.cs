using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static System.Security.Cryptography.CryptoConfig;
using static OpenGost.Security.Cryptography.CryptoConstants;
using static OpenGost.Security.Cryptography.Properties.CryptographyStrings;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Verifies a <see cref="GostECDsa256"/> signature.
    /// </summary>
    [ComVisible(true)]
    public class GostECDsa256SignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private readonly string _oid;
        private GostECDsa256 _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa256SignatureDeformatter"/> class.
        /// </summary>
        public GostECDsa256SignatureDeformatter()
        {
            _oid = MapNameToOID(Streebog256AlgorithmFullName);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa256SignatureDeformatter"/> class with the specified key.
        /// </summary>
        /// <param name="key">
        /// The instance of <see cref="GostECDsa256"/> that holds the key.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key"/> is <see langword="null"/>.
        /// </exception>
        public GostECDsa256SignatureDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _key = (GostECDsa256)key;
        }

        /// <summary>
        /// Specifies the hash algorithm for the <see cref="GostECDsa256"/> signature deformatter.
        /// </summary>
        /// <param name="strName">
        /// The name of the hash algorithm to use for the signature deformatter. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="strName"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// The <paramref name="strName"/> parameter does not map to the <see cref="Streebog256"/>
        /// hash algorithm.
        /// </exception>
        public override void SetHashAlgorithm(string strName)
        {
            if (strName == null)
                throw new ArgumentNullException(nameof(strName));
            if (MapNameToOID(strName) != _oid)
                throw new CryptographicUnexpectedOperationException(CryptographicInvalidOperation);
        }

        /// <summary>
        /// Specifies the key to be used for the <see cref="GostECDsa256"/> signature deformatter.
        /// </summary>
        /// <param name="key">
        /// The instance of <see cref="GostECDsa256"/> that holds the key. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key"/> is <see langword="null"/>.
        /// </exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _key = (GostECDsa256)key;
        }

        /// <summary>
        /// Verifies the <see cref="GostECDsa256"/> signature on the data.
        /// </summary>
        /// <param name="rgbHash">
        /// The data signed with <paramref name="rgbSignature"/>.
        /// </param>
        /// <param name="rgbSignature">
        /// The signature to be verified for <paramref name="rgbHash"/>. 
        /// </param>
        /// <returns>
        /// <see langword="true"/> if the signature is valid for the data;
        /// otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="rgbHash"/> is <see langword="null"/>.
        /// -or-
        /// <paramref name="rgbSignature"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// The <see cref="GostECDsa256"/> key is missing.
        /// </exception>
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            if (rgbHash == null)
                throw new ArgumentNullException(nameof(rgbHash));
            if (rgbSignature == null)
                throw new ArgumentNullException(nameof(rgbSignature));
            if (_key == null)
                throw new CryptographicUnexpectedOperationException(CryptographicMissingKey);

            return _key.VerifyHash(rgbHash, rgbSignature);
        }
    }
}
