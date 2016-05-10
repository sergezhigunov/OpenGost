using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    internal sealed class MagmaManagedTransform : SymmetricTransform
    {
        #region Constants

        private static readonly byte[][] s_substitutionBox =
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
            s_lookupTable0 = InitializeLookupTable(0),
            s_lookupTable1 = InitializeLookupTable(1),
            s_lookupTable2 = InitializeLookupTable(2),
            s_lookupTable3 = InitializeLookupTable(3);

        #endregion

        private uint[] _keyExpansion;

        public MagmaManagedTransform(
            byte[] rgbKey,
            byte[] rgbIV,
            int blockSize,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTransformMode transformMode)
            : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
        { }

        [SecuritySafeCritical]
        protected unsafe override void GenerateKeyExpansion(byte[] rgbKey)
        {
            _keyExpansion = new uint[8];

            fixed (uint* keyExpansion = _keyExpansion)
                fixed (byte* key = rgbKey)
                    UInt32FromBigEndian(keyExpansion, 8, key);
        }

        [SecuritySafeCritical]
        protected unsafe override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint a0, a1;

            LoadRegisters(inputBuffer, inputOffset, out a0, out a1);

            fixed (uint* k = _keyExpansion, lookup0 = s_lookupTable0, lookup1 = s_lookupTable1, lookup2 = s_lookupTable2, lookup3 = s_lookupTable3)
            {
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
                ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            }

            FlushRegisters(outputBuffer, outputOffset, a0, a1);
        }

        [SecuritySafeCritical]
        protected unsafe override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint a0, a1;

            LoadRegisters(inputBuffer, inputOffset, out a0, out a1);

            fixed (uint* k = _keyExpansion, lookup0 = s_lookupTable0, lookup1 = s_lookupTable1, lookup2 = s_lookupTable2, lookup3 = s_lookupTable3)
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
                byte* block = input + inputOffset;

                a0 = UInt32FromBigEndian(block + sizeof(uint));
                a1 = UInt32FromBigEndian(block);
            }
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void FlushRegisters(byte[] outputBuffer, int outputOffset, uint a0, uint a1)
        {
            fixed (byte* output = outputBuffer)
            {
                byte* block = output + outputOffset;

                UInt32ToBigEndian(block, a0);
                UInt32ToBigEndian(block + sizeof(uint), a1);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                EraseData(ref _keyExpansion);
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
        private unsafe static void ComputeEightRoundsBackwardKeyOrder(uint* k, uint* lookup0, uint* lookup1, uint* lookup2, uint* lookup3, ref uint a0, ref uint a1)
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
        private unsafe static uint SubstituteAndRotateElevenBits(uint data, uint* lookup0, uint* lookup1, uint* lookup2, uint* lookup3)
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

            for (int b = 0; b < 256; b++)
                lookupTable[b] = RotateElevenBitsLeft((s_substitutionBox[2 * tableNumber][b & 0x0f] ^
                    (uint)s_substitutionBox[2 * tableNumber + 1][b >> 4] << 4) << tableNumber * 8);

            return lookupTable;
        }
    }
}