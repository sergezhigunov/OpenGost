using System.Runtime.InteropServices;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Accesses the managed version of the <see cref="Grasshopper"/> algorithm. This class cannot be inherited.
/// </summary>
[ComVisible(true)]
public sealed class GrasshopperManaged : Grasshopper
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
    /// Initializes a new instance of the <see cref="Grasshopper"/> class.
    /// </summary>
    public GrasshopperManaged()
    { }

    /// <summary>
    /// Creates a symmetric <see cref="Grasshopper"/> decryptor object
    /// with the specified key and initialization vector.
    /// </summary>
    /// <param name="rgbKey">
    /// The secret key to be used for the symmetric algorithm. The key size must be 256 bits.
    /// </param>
    /// <param name="rgbIV">
    /// The initialization vector to be used for the symmetric algorithm.
    /// </param>
    /// <returns>
    /// A symmetric <see cref="Grasshopper"/> decryptor object.
    /// </returns>
    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        => new GrasshopperManagedTransform(rgbKey, rgbIV, BlockSize, Mode, Padding, false);

    /// <summary>
    /// Creates a symmetric <see cref="Grasshopper"/> encryptor object
    /// with the specified key and initialization vector.
    /// </summary>
    /// <param name="rgbKey">
    /// The secret key to be used for the symmetric algorithm. The key size must be 256 bits.
    /// </param>
    /// <param name="rgbIV">
    /// The initialization vector to be used for the symmetric algorithm.
    /// </param>
    /// <returns>
    /// A symmetric <see cref="Grasshopper"/> encryptor object.
    /// </returns>
    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        => new GrasshopperManagedTransform(rgbKey, rgbIV, BlockSize, Mode, Padding, true);

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
