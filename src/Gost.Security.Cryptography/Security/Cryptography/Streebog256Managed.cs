using System;

namespace Gost.Security.Cryptography
{
    using static Buffer;

    /// <summary>
    /// Computes the <see cref="Streebog256"/> hash for the input data using the managed implementation. 
    /// </summary>
    public class Streebog256Managed : Streebog256
    {
        private static readonly byte[] s_iv =
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        private readonly Streebog512Managed _innerAlgorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="Streebog256Managed"/> class.
        /// </summary>
        public Streebog256Managed()
        {
            _innerAlgorithm = new Streebog512Managed(s_iv);
        }

        /// <summary>
        /// Initializes an instance of <see cref="Streebog256Managed"/>.
        /// </summary>
        public override void Initialize()
        {
            _innerAlgorithm.Initialize();
        }

        /// <summary>
        /// Routes data written to the object into the <see cref="Streebog256"/> hash algorithm for computing the hash.
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
            _innerAlgorithm.TransformBlock(data, dataOffset, dataSize, null, 0);
        }

        /// <summary>
        /// Returns the computed <see cref="Streebog256"/> hash value after all data has been written to the object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected override byte[] HashFinal()
        {
            _innerAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
            byte[] hash = new byte[32];
            BlockCopy(_innerAlgorithm.Hash, 32, hash, 0, 32);
            return hash;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="Streebog256"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// true to release both managed and unmanaged resources;
        /// false to release only unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            _innerAlgorithm.Dispose();
        }
    }
}
