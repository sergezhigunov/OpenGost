using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Computes the <see cref="Streebog256"/> hash for the input data. 
    /// </summary>
    public abstract class Streebog256 : HashAlgorithm
    {
        /// <summary>
        /// Initializes an instance of <see cref="Streebog256"/>.
        /// </summary>
        protected Streebog256()
        {
            HashSizeValue = 256;
        }
    }
}
