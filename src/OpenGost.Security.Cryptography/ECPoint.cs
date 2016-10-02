using System.Diagnostics.CodeAnalysis;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Represents a point on an elliptic curve.
    /// </summary>
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