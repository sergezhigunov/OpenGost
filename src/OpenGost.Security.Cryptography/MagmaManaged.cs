using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Accesses the managed version of the <see cref="Magma"/> algorithm. This class cannot be inherited.
    /// </summary>
    [ComVisible(true)]
    public sealed class MagmaManaged : Magma
    {
        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        /// <returns>
        /// The mode for operation of the symmetric algorithm. The default is <see cref="CipherMode.CBC"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        /// The cipher mode is not one of the following values:
        /// <see cref="CipherMode.CBC"/>, <see cref="CipherMode.ECB"/>,
        /// <see cref="CipherMode.OFB"/>, <see cref="CipherMode.CFB"/>.
        /// </exception>
        public override CipherMode Mode
        {
            set
            {
                if (value < CipherMode.CBC || CipherMode.CFB < value)
                    throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);

                ModeValue = value;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Magma"/> class.
        /// </summary>
        public MagmaManaged()
        { }

        /// <summary>
        /// Creates a symmetric <see cref="Magma"/> decryptor object with the specified key and initialization vector.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key to be used for the symmetric algorithm. The key size must be 256 bits.
        /// </param>
        /// <param name="rgbIV">
        /// The initialization vector to be used for the symmetric algorithm.
        /// </param>
        /// <returns>
        /// A symmetric <see cref="Magma"/> decryptor object.
        /// </returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new MagmaManagedTransform(rgbKey, rgbIV, BlockSize, Mode, Padding, SymmetricTransformMode.Decrypt);
        }

        /// <summary>
        /// Creates a symmetric <see cref="Magma"/> encryptor object with the specified key and initialization vector.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key to be used for the symmetric algorithm. The key size must be 256 bits.
        /// </param>
        /// <param name="rgbIV">
        /// The initialization vector to be used for the symmetric algorithm.
        /// </param>
        /// <returns>
        /// A symmetric <see cref="Magma"/> encryptor object.
        /// </returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new MagmaManagedTransform(rgbKey, rgbIV, BlockSize, Mode, Padding, SymmetricTransformMode.Encrypt);
        }

        /// <summary>
        /// Generates a random initialization vector to be used for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = CryptoUtils.GenerateRandomBytes(FeedbackSizeValue / 8);
        }

        /// <summary>
        /// Generates a random key to be used for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = CryptoUtils.GenerateRandomBytes(KeySizeValue / 8);
        }
    }
}
