using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Computes the <see cref="Streebog512"/> hash for the input data. 
    /// </summary>
    public abstract class Streebog512 : HashAlgorithm
    {
        /// <summary>
        /// Initializes an instance of <see cref="Streebog512"/>.
        /// </summary>
        protected Streebog512()
        {
            HashSizeValue = 512;
        }
    }
}
