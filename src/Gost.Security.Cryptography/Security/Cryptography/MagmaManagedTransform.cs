using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    internal sealed class MagmaManagedTransform : SymmetricTransform
    {
        private static readonly byte[][] s_substTable = new byte[][]
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

        private static readonly uint[]
            s_lookupTable0,
            s_lookupTable1,
            s_lookupTable2,
            s_lookupTable3;

        private uint[] _keyExpansion;

        static MagmaManagedTransform()
        {
            s_lookupTable0 = new uint[256];
            s_lookupTable1 = new uint[256];
            s_lookupTable2 = new uint[256];
            s_lookupTable3 = new uint[256];

            for (int data = 0; data < 256; data++)
            {
                int
                    high = (data & 0xf0) >> 4,
                    low = data & 0x0f;

                s_lookupTable0[data] = RotateElevenBitsLeft(s_substTable[0][low] ^ (uint)s_substTable[1][high] << 4);
                s_lookupTable1[data] = RotateElevenBitsLeft((s_substTable[2][low] ^ (uint)s_substTable[3][high] << 4) << 8);
                s_lookupTable2[data] = RotateElevenBitsLeft((s_substTable[4][low] ^ (uint)s_substTable[5][high] << 4) << 16);
                s_lookupTable3[data] = RotateElevenBitsLeft((s_substTable[6][low] ^ (uint)s_substTable[7][high] << 4) << 24);
            }

        }

        public MagmaManagedTransform(byte[] rgbKey, byte[] rgbIV, int blockSize, int feedbackSize, CipherMode cipherMode, PaddingMode paddingMode, SymmetricTransformMode transformMode)
            : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
        { }

        protected override void GenerateKeyExpansion(byte[] rgbKey)
        {
            _keyExpansion = new uint[8];
            for (int i = 0; i < 8; i++)
                _keyExpansion[i] = ToUInt32(rgbKey, i * 4);
        }

        protected override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint
                a0 = ToUInt32(inputBuffer, inputOffset + 4),
                a1 = ToUInt32(inputBuffer, inputOffset);

            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);

            CopyUInt32To(outputBuffer, outputOffset, a0);
            CopyUInt32To(outputBuffer, outputOffset + 4, a1);
        }

        protected override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            uint
                a0 = ToUInt32(inputBuffer, inputOffset + 4),
                a1 = ToUInt32(inputBuffer, inputOffset);

            ComputeEightRoundsForwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(_keyExpansion, ref a0, ref a1);

            CopyUInt32To(outputBuffer, outputOffset, a0);
            CopyUInt32To(outputBuffer, outputOffset + 4, a1);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                EraseData(ref _keyExpansion);
            }
            base.Dispose(disposing);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CopyUInt32To(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static uint ToUInt32(byte[] buffer, int offset)
        {
            return buffer[offset + 3] | ((uint)buffer[offset + 2]) << 8 | ((uint)buffer[offset + 1]) << 16 | ((uint)buffer[offset]) << 24;
        }

        private static uint RotateElevenBitsLeft(uint input)
        {
            return input << 11 | input >> 21;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint SubstituteAndRotateElevenBits(uint data)
        {
            return
                s_lookupTable0[data & 0xff] |
                s_lookupTable1[(data >> 8) & 0xff] |
                s_lookupTable2[(data >> 16) & 0xff] |
                s_lookupTable3[(data >> 24) & 0xff];
        }
    }
}
