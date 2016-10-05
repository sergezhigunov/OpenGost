#if NET45
namespace OpenGost.Security.Cryptography
{
    public partial struct ECCurve
    {
        /// <summary>
        /// Represents the type of elliptic curve.
        /// </summary>
        public enum ECCurveType
        {
            /// <summary>
            /// The elliptic curve is implicit elliptic curve.
            /// </summary>
            Implicit = 0,

            /// <summary>
            /// The elliptic curve is prime short Weierstrass elliptic curve.
            /// </summary>
            PrimeShortWeierstrass = 1,

            /// <summary>
            /// The elliptic curve is prime twisted Edwards elliptic curve.
            /// </summary>
            PrimeTwistedEdwards = 2,

            /// <summary>
            /// The elliptic curve is prime Montgomery elliptic curve.
            /// </summary>
            PrimeMontgomery = 3,

            /// <summary>
            /// The elliptic curve is characteristic 2 elliptic curve.
            /// </summary>
            Characteristic2 = 4,

            /// <summary>
            /// The elliptic curve is named elliptic curve.
            /// </summary>
            Named = 5,
        }
    }
} 
#endif
