using System;
using System.Runtime.InteropServices;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Specifies the direction of the symmetric transform.
    /// </summary>
    [Serializable]
    [ComVisible(true)]
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
