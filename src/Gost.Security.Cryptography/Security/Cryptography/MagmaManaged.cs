using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static Utils;

    /// <summary>
    /// Accesses the managed version of the <see cref="Magma"/> algorithm. This class cannot be inherited.
    /// </summary>
    public sealed class MagmaManaged : Magma
    {
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
            return new MagmaManagedTransform(rgbKey, rgbIV, BlockSize, FeedbackSize, Mode, Padding, SymmetricTransformMode.Decrypt);
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
            return new MagmaManagedTransform(rgbKey, rgbIV, BlockSize, FeedbackSize, Mode, Padding, SymmetricTransformMode.Encrypt);
        }

        /// <summary>
        /// Generates a random initialization vector to be used for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            KeyValue = GenerateRandomBytes(FeedbackSizeValue / 8);
        }

        /// <summary>
        /// Generates a random key to be used for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = GenerateRandomBytes(KeySizeValue / 8);
        }
    }
}
