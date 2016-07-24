﻿using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoConfig;
    using static CryptoConstants;

    /// <summary>
    /// Computes the <see cref="Streebog512"/> hash for the input data. 
    /// </summary>
    [ComVisible(true)]
    public abstract class Streebog512 : HashAlgorithm
    {
        /// <summary>
        /// Initializes an instance of <see cref="Streebog512"/>.
        /// </summary>
        protected Streebog512()
        {
            HashSizeValue = 512;
        }

        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="Streebog512"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="Streebog512"/>.
        /// </returns>
        [ComVisible(false)]
        public new static Streebog512 Create()
            => Create(Streebog512AlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="Streebog512"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="Streebog512"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="Streebog512"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public new static Streebog512 Create(string algorithmName)
            => (Streebog512)CreateFromName(algorithmName);

        #endregion
    }
}
