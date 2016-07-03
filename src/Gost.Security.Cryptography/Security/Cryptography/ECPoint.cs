using System;
using System.Diagnostics.CodeAnalysis;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Represents a point on an elliptic curve.
    /// </summary>
    [Serializable]
    [SuppressMessage("Microsoft.Performance", "CA1815:OverrideEqualsAndOperatorEqualsOnValueTypes")]
    public struct ECPoint
    {
        /// <summary>
        /// The x-coordinate of current elliptic point.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields")]
        public byte[] X;

        /// <summary>
        /// The y-coordinate of current elliptic point.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields")]
        public byte[] Y;
    }
}