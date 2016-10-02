using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConstants;

    /// <summary>
    /// Contains information about the properties of the 512-bit 
    /// GOST Elliptic Curve Digital Signature (GOST R 34.10-2012).
    /// </summary>
    public class GostECDsa512SignatureDescription : SignatureDescription
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GostECDsa512SignatureDescription"/> class.
        /// </summary>
        public GostECDsa512SignatureDescription()
        {
            KeyAlgorithm = GostECDsa512AlgorithmFullName;
            DigestAlgorithm = Streebog512AlgorithmFullName;
            FormatterAlgorithm = GostECDsa512SignatureFormatterFullName;
            DeformatterAlgorithm = GostECDsa512SignatureDeformatterFullName;
        }
    }
}
