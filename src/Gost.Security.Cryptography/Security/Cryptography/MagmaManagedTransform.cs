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

        protected override void GenerateKeyExpansion(byte[] rgbKey)
        {
            _keyExpansion = new uint[8];
            for (int i = 0; i < 8; i++)
                _keyExpansion[i] = UInt32FromBigEndian(rgbKey, i * 4);
        }

        protected override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint
                a0 = UInt32FromBigEndian(inputBuffer, inputOffset + 4),
                a1 = UInt32FromBigEndian(inputBuffer, inputOffset);

            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);

            UInt32ToBigEndian(a0, outputBuffer, outputOffset);
            UInt32ToBigEndian(a1, outputBuffer, outputOffset + 4);
        }

        protected override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint
                a0 = UInt32FromBigEndian(inputBuffer, inputOffset + 4),
                a1 = UInt32FromBigEndian(inputBuffer, inputOffset);

            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);

            UInt32ToBigEndian(a0, outputBuffer, outputOffset);
            UInt32ToBigEndian(a1, outputBuffer, outputOffset + 4);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                EraseData(ref _keyExpansion);
            }
            base.Dispose(disposing);
        }

        private static void ComputeEightRoundsForwardKeyOrder(uint[] k, ref uint a0, ref uint a1)
        {
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[0]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[1]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[2]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[3]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[4]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[5]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[6]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[7]);
        }

        private static void ComputeEightRoundsBackwardKeyOrder(uint[] k, ref uint a0, ref uint a1)
        {
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[7]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[6]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[5]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[4]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[3]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[2]);
            a1 ^= SubstituteAndRotateElevenBits(a0 + k[1]);
            a0 ^= SubstituteAndRotateElevenBits(a1 + k[0]);
        }

        private static uint RotateElevenBitsLeft(uint input)
        {
            return input << 11 | input >> 21;
        }

        private static uint SubstituteAndRotateElevenBits(uint data)
        {
            // Substitution and rotation precomputed in the lookup tables
            return
                s_lookupTable0[data & 0xff] |
                s_lookupTable1[(data >> 8) & 0xff] |
                s_lookupTable2[(data >> 16) & 0xff] |
                s_lookupTable3[(data >> 24) & 0xff];
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
