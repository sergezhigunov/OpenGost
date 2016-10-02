#if NET45
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    using static SecurityCryptographyStrings;

    /// <summary>
    /// Represents the public and private key of the specified elliptic curve.
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1815:OverrideEqualsAndOperatorEqualsOnValueTypes")]
    public struct ECParameters
    {
        /// <summary>
        /// Public point.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields")]
        public ECPoint Q;

        /// <summary>
        /// Private Key. Not always present.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields")]
        public byte[] D;

        /// <summary>
        /// The elliptic curve.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields")]
        public ECCurve Curve;

        /// <summary>
        /// Validate the current object.
        /// </summary>
        /// <exception cref="CryptographicException">
        /// Key or curve parameters are not valid.
        /// </exception>
        public void Validate()
        {
            bool hasErrors = false;

            byte[] x = Q.X, y = Q.Y;

            if (x == null || y == null || x.Length != y.Length)
                hasErrors = true;

            if (!hasErrors)
            {
                // Explicit curves require D length to match Curve.Order
                hasErrors = (D != null && (D.Length != Curve.Order.Length));
            }

            if (hasErrors)
                throw new CryptographicException(CryptographicInvalidCurveKeyParameters);

            Curve.Validate();
        }
    }
}

#endif
