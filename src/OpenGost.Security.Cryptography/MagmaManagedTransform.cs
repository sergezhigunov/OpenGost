using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    /// <summary>
    /// Performs a cryptographic transformation of data using the <see cref="Magma"/> algorithm.
    /// This class cannot be inherited.
    /// </summary>
    [ComVisible(true)]
    [SuppressMessage("Microsoft.Interoperability", "CA1409:ComVisibleTypesShouldBeCreatable")]
    public sealed class MagmaManagedTransform : SymmetricTransform
    {
        #region Constants

        private static readonly byte[][] _substitutionBox =
        {
            new byte[] { 0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1 },
            new byte[] { 0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF },
            new byte[] { 0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0 },
            new byte[] { 0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB },
            new byte[] { 0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC },
            new byte[] { 0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0 },
            new byte[] { 0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7 },
            new byte[] { 0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2 }
        };

        #endregion

        #region Lookup tables

        private static readonly uint[]
            _lookup0 = InitializeLookupTable(0),
            _lookup1 = InitializeLookupTable(1),
            _lookup2 = InitializeLookupTable(2),
            _lookup3 = InitializeLookupTable(3);

        #endregion

        private uint[] _keyExpansion;

        internal MagmaManagedTransform(
            byte[] rgbKey,
            byte[] rgbIV,
            int blockSize,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTransformMode transformMode)
            : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
        { }

        /// <summary>
        /// Initializes the private key expansion.
        /// </summary>
        /// <param name="key">
        /// The private key to be used for the key expansion.
        /// </param>
        [SecuritySafeCritical]
        protected override unsafe void GenerateKeyExpansion(byte[] key)
        {
            _keyExpansion = new uint[8];

            fixed (uint* keyExpansion = _keyExpansion)
                fixed (byte* keyPtr = key)
                CryptoUtils.UInt32FromBigEndian(keyExpansion, 8, keyPtr);
        }

        /// <summary>
        /// Implements the block cipher encryption function of <see cref="MagmaManaged"/> algorithm.
        /// </summary>
        /// <param name="inputBuffer">
        /// The input to perform the operation on.
        /// </param>
        /// <param name="inputOffset">
        /// The offset into the input byte array to begin using data from.
        /// </param>
        /// <param name="outputBuffer">
        /// The output to write the data to.
        /// </param>
        /// <param name="outputOffset">
        /// The offset into the output byte array to begin writing data to.
        /// </param>
        [SecuritySafeCritical]
        protected override unsafe void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            LoadRegisters(inputBuffer, inputOffset, out var a0, out var a1);

            fixed (uint* k = _keyExpansion, lookup0 = _lookup0, lookup1 = _lookup1, lookup2 = _lookup2, lookup3 = _lookup3)
            {
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            }

            FlushRegisters(outputBuffer, outputOffset, a0, a1);
        }

        /// <summary>
        /// Implements the block cipher decryption function of <see cref="MagmaManaged"/> algorithm.
        /// </summary>
        /// <param name="inputBuffer">
        /// The input to perform the operation on.
        /// </param>
        /// <param name="inputOffset">
        /// The offset into the input byte array to begin using data from.
        /// </param>
        /// <param name="outputBuffer">
        /// The output to write the data to.
        /// </param>
        /// <param name="outputOffset">
        /// The offset into the output byte array to begin writing data to.
        /// </param>
        [SecuritySafeCritical]
        protected override unsafe void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            LoadRegisters(inputBuffer, inputOffset, out var a0, out var a1);

            fixed (uint* k = _keyExpansion, lookup0 = _lookup0, lookup1 = _lookup1, lookup2 = _lookup2, lookup3 = _lookup3)
            {
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            }

            FlushRegisters(outputBuffer, outputOffset, a0, a1);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void LoadRegisters(byte[] inputBuffer, int inputOffset, out uint a0, out uint a1)
        {
            fixed (byte* input = inputBuffer)
            {
                var block = input + inputOffset;

                a0 = CryptoUtils.UInt32FromBigEndian(block + sizeof(uint));
                a1 = CryptoUtils.UInt32FromBigEndian(block);
            }
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void FlushRegisters(byte[] outputBuffer, int outputOffset, uint a0, uint a1)
        {
            fixed (byte* output = outputBuffer)
            {
                var block = output + outputOffset;

                CryptoUtils.UInt32ToBigEndian(block, a0);
                CryptoUtils.UInt32ToBigEndian(block + sizeof(uint), a1);
            }
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="MagmaManagedTransform" />
        /// class and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources;
        /// <see langword="false"/> to release only unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CryptoUtils.EraseData(ref _keyExpansion);
            }
            base.Dispose(disposing);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void ComputeEightRoundsForwardKeyOrder(uint* k, uint* lookup0, uint* lookup1, uint* lookup2, uint* lookup3, ref uint a0, ref uint a1)
        {
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[0], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[1], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[2], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[3], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[4], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[5], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[6], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[7], lookup0, lookup1, lookup2, lookup3);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void ComputeEightRoundsBackwardKeyOrder(uint* k, uint* lookup0, uint* lookup1, uint* lookup2, uint* lookup3, ref uint a0, ref uint a1)
        {
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[7], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[6], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[5], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[4], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[3], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[2], lookup0, lookup1, lookup2, lookup3);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[1], lookup0, lookup1, lookup2, lookup3);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[0], lookup0, lookup1, lookup2, lookup3);
        }

        private static uint RotateElevenBitsLeft(uint input)
        {
            return input << 11 | input >> 21;
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe uint SubstituteAndRotateElevenBits(uint data, uint* lookup0, uint* lookup1, uint* lookup2, uint* lookup3)
        {
            // Substitution and rotation precomputed in the lookup tables
            return
                lookup0[(byte)data] |
                lookup1[(byte)(data >> 8)] |
                lookup2[(byte)(data >> 16)] |
                lookup3[data >> 24];
        }

        private static uint[] InitializeLookupTable(int tableNumber)
        {
            var lookupTable = new uint[256];

            for (var b = 0; b < 256; b++)
                lookupTable[b] = RotateElevenBitsLeft((_substitutionBox[2 * tableNumber][b & 0x0f] ^
                    (uint)_substitutionBox[2 * tableNumber + 1][b >> 4] << 4) << tableNumber * 8);

            return lookupTable;
        }
    }
}
