using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Contains information about the properties of the 256-bit
    /// GOST Elliptic Curve Digital Signature (GOST R 34.10-2012).
    /// </summary>
    public class GostECDsa256SignatureDescription : SignatureDescription
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa256SignatureDescription"/> class.
        /// </summary>
        public GostECDsa256SignatureDescription()
        {
            KeyAlgorithm = CryptoConstants.GostECDsa256AlgorithmFullName;
            DigestAlgorithm = CryptoConstants.Streebog256AlgorithmFullName;
            FormatterAlgorithm = CryptoConstants.GostECDsa256SignatureFormatterFullName;
            DeformatterAlgorithm = CryptoConstants.GostECDsa256SignatureDeformatterFullName;
        }
    }
}
