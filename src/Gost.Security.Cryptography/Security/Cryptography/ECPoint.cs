using System;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Represents a point on an elliptic curve.
    /// </summary>
    [Serializable]
    public struct ECPoint
    {
        /// <summary>
        /// The x-coordinate of current elliptic point.
        /// </summary>
        public byte[] X;

        /// <summary>
        /// The x-coordinate of current elliptic point.
        /// </summary>
        public byte[] Y;
    }
}