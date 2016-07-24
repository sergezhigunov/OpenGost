using System;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Specifies the direction of the symmetric transform. 
    /// </summary>
    [Serializable]
    public enum SymmetricTransformMode
    {
        /// <summary>
        /// The symmetric transform is encryption
        /// </summary>
        Encrypt = 0,

        /// <summary>
        /// The symmetric transform is decryption
        /// </summary>
        Decrypt = 1
    }
}
