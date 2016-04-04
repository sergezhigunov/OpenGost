using System;

namespace Gost.Security.Cryptography
{
    /// <summary>
    /// Computes the <see cref="Streebog512"/> hash for the input data using the managed implementation. 
    /// </summary>
    public class Streebog512Managed : Streebog512
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Streebog512Managed"/> class.
        /// </summary>
        public Streebog512Managed()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Initializes an instance of <see cref="Streebog512Managed"/>.
        /// </summary>
        public override void Initialize()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Routes data written to the object into the <see cref="Streebog512"/> hash algorithm for computing the hash.
        /// </summary>
        /// <param name="data">
        /// The input data. 
        /// </param>
        /// <param name="dataOffset">
        /// The offset into the byte array from which to begin using data. 
        /// </param>
        /// <param name="dataSize">
        /// The number of bytes in the array to use as data. 
        /// </param>
        protected override void HashCore(byte[] data, int dataOffset, int dataSize)
        {
            throw new NotImplementedException();
        }
        /// <summary>
        /// Returns the computed <see cref="Streebog512"/> hash value after all data has been written to the object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }
    }
}