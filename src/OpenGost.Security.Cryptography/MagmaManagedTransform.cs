using System.Numerics;
using System.Runtime.CompilerServices;

namespace OpenGost.Security.Cryptography;

internal sealed class MagmaManagedTransform : SymmetricTransform
{
    #region Lookup tables

    private static readonly uint[] _lookup = InitializeLookupTable();

    #endregion

    private uint[]? _keyExpansion;

    internal MagmaManagedTransform(
        byte[] rgbKey,
        byte[]? rgbIV,
        int blockSize,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        bool encrypting)
        : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, encrypting)
    { }

    protected override unsafe void GenerateKeyExpansion(byte[] key)
    {
        _keyExpansion = new uint[8];

        fixed (uint* keyExpansion = _keyExpansion)
        fixed (byte* keyPtr = key)
            CryptoUtils.UInt32FromBigEndian(keyExpansion, 8, keyPtr);
    }

    protected override unsafe void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
    {
        LoadRegisters(inputBuffer, inputOffset, out var a0, out var a1);

        fixed (uint* k = _keyExpansion, lookup0 = _lookup)
        {
            var lookup1 = lookup0 + 256;
            var lookup2 = lookup0 + 256 * 2;
            var lookup3 = lookup0 + 256 * 3;
            ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
        }

        FlushRegisters(outputBuffer, outputOffset, a0, a1);
    }

    protected override unsafe void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
    {
        LoadRegisters(inputBuffer, inputOffset, out var a0, out var a1);

        fixed (uint* k = _keyExpansion, lookup0 = _lookup)
        {
            var lookup1 = lookup0 + 256;
            var lookup2 = lookup0 + 256 * 2;
            var lookup3 = lookup0 + 256 * 3;
            ComputeEightRoundsForwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
            ComputeEightRoundsBackwardKeyOrder(k, lookup0, lookup1, lookup2, lookup3, ref a0, ref a1);
        }

        FlushRegisters(outputBuffer, outputOffset, a0, a1);
    }

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

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptoUtils.EraseData(ref _keyExpansion);
        }
        base.Dispose(disposing);
    }

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

    private static uint[] InitializeLookupTable()
    {
#if NET5_0_OR_GREATER
        var lookupTable = GC.AllocateArray<uint>(256 * 4, true);
#else
        var lookupTable = new uint[256 * 4];
#endif
        unsafe
        {
            byte* substitutionBox = stackalloc byte[]
            {
                0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1,
                0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF,
                0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0,
                0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB,
                0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC,
                0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0,
                0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7,
                0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2,
            };

            fixed (uint* lookupTableFixed = lookupTable)
                for (var tableNumber = 0; tableNumber < 4; tableNumber++)
                {
                    var section = tableNumber << 3;
                    var shift = section << 2;
                    var sbox1 = substitutionBox + shift;
                    var sbox2 = substitutionBox + shift + 16;
                    var lookup = lookupTableFixed + (shift << 3);
                    for (var a = 0; a < 256; a += 4)
                    {
                        InitializeSubstituteAndRotateElevenBits(lookup, sbox1, sbox2, a, section);
                        InitializeSubstituteAndRotateElevenBits(lookup, sbox1, sbox2, a + 1, section);
                        InitializeSubstituteAndRotateElevenBits(lookup, sbox1, sbox2, a + 2, section);
                        InitializeSubstituteAndRotateElevenBits(lookup, sbox1, sbox2, a + 3, section);
                    }
                }
        }

        return lookupTable;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void InitializeSubstituteAndRotateElevenBits(
        uint* lookup,
        byte* sbox1,
        byte* sbox2,
        int b,
        int shift)
    {
#if NET5_0_OR_GREATER
        lookup[b] = BitOperations.RotateLeft(offset: 11, value: (sbox1[b & 0x0f] ^ (uint)sbox2[b >> 4] << 4) << shift);
    }
#else
        lookup[b] = RotateElevenBitsLeft((sbox1[b & 0x0f] ^ (uint)sbox2[b >> 4] << 4) << shift);
    }

    private static uint RotateElevenBitsLeft(uint input)
    {
        return input << 11 | input >> 21;
    }
#endif
}
