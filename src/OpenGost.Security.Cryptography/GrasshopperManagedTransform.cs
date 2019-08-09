using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace OpenGost.Security.Cryptography
{
    using static Buffer;
    using static CryptoUtils;

    /// <summary>
    /// Performs a cryptographic transformation of data using the <see cref="Grasshopper"/>
    /// algorithm. This class cannot be inherited.
    /// </summary>
    [ComVisible(true)]
    [SuppressMessage("Microsoft.Interoperability", "CA1409:ComVisibleTypesShouldBeCreatable")]
    public sealed class GrasshopperManagedTransform : SymmetricTransform
    {
        #region Constants

        private static readonly byte[]
            s_forwardSubstitutionBox =
            {
                0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
                0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
                0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
                0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
                0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
                0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
                0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
                0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
                0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
                0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
                0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
                0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
                0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
                0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
                0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
                0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
            },
            s_backwardSubstitutionBox =
            {
                0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
                0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
                0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
                0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
                0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
                0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
                0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
                0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
                0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
                0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
                0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
                0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
                0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
                0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
                0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
                0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74,
            };

        #endregion

        #region Lookup tables

        private static readonly byte[]
            s_lookupTable16 = InitializeLookupTable(16),
            s_lookupTable32 = InitializeLookupTable(32),
            s_lookupTable133 = InitializeLookupTable(133),
            s_lookupTable148 = InitializeLookupTable(148),
            s_lookupTable192 = InitializeLookupTable(192),
            s_lookupTable194 = InitializeLookupTable(194),
            s_lookupTable251 = InitializeLookupTable(251);

        private static readonly byte[][][] s_iterationConstants = InitializeIterationConstants();

        #endregion

        private byte[][] _keyExpansion;

        internal GrasshopperManagedTransform(
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
        protected override void GenerateKeyExpansion(byte[] key)
        {
            _keyExpansion = new byte[10][]
            {
                new byte[16], new byte[16],
                null, null, null, null, null, null, null, null
            };
            BlockCopy(key, 0, _keyExpansion[0], 0, 16);
            BlockCopy(key, 16, _keyExpansion[1], 0, 16);

            unsafe
            {
                var t = stackalloc byte[16];

                fixed (byte* s = s_forwardSubstitutionBox,
                    t16 = s_lookupTable16,
                    t32 = s_lookupTable32,
                    t133 = s_lookupTable133,
                    t148 = s_lookupTable148,
                    t192 = s_lookupTable192,
                    t194 = s_lookupTable194,
                    t251 = s_lookupTable251)
                {
                    for (var i = 0; i < 4; i++)
                    {
                        _keyExpansion[2 * i + 2] = (byte[])_keyExpansion[2 * i].Clone();
                        _keyExpansion[2 * i + 3] = (byte[])_keyExpansion[2 * i + 1].Clone();

                        fixed (byte* l = _keyExpansion[2 * i + 2], h = _keyExpansion[2 * i + 3])
                        {
                            for (var j = 0; j < 8; j++)
                            {
                                fixed (byte* c = s_iterationConstants[i][j])
                                    Xor(c, l, t);

                                Substitute(s, t);
                                DoLinearTransformForward(t, t16, t32, t133, t148, t192, t194, t251);
                                Xor(t, h);
                                Copy(l, h);
                                Copy(t, l);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="GrasshopperManagedTransform" />
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
                EraseData(ref _keyExpansion);
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Implements the block cipher encryption function of <see cref="GrasshopperManaged"/> algorithm.
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
        protected override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            unsafe
            {
                fixed (byte* input = inputBuffer, output = outputBuffer)
                    EncryptBlock(_keyExpansion, input + inputOffset, output + outputOffset);
            }
        }

        /// <summary>
        /// Implements the block cipher decryption function of <see cref="GrasshopperManaged"/> algorithm.
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
        protected override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            unsafe
            {
                fixed (byte* input = inputBuffer, output = outputBuffer)
                    DecryptBlock(_keyExpansion, input + inputOffset, output + outputOffset);
            }
        }

        [SecurityCritical]
        private static unsafe void EncryptBlock(byte[][] keyExpansion, byte* input, byte* output)
        {

            fixed (byte* k = keyExpansion[0])
                Xor(input, k, output);

            fixed (byte* s = s_forwardSubstitutionBox,
                t16 = s_lookupTable16,
                t32 = s_lookupTable32,
                t133 = s_lookupTable133,
                t148 = s_lookupTable148,
                t192 = s_lookupTable192,
                t194 = s_lookupTable194,
                t251 = s_lookupTable251)
            {
                for (var i = 1; i < 10; i++)
                {
                    Substitute(s, output);
                    DoLinearTransformForward(output, t16, t32, t133, t148, t192, t194, t251);

                    fixed (byte* k = keyExpansion[i])
                        Xor(output, k);
                }
            }
        }

        [SecurityCritical]
        private static unsafe void DecryptBlock(byte[][] keyExpansion, byte* input, byte* output)
        {
            fixed (byte* k = keyExpansion[9])
                Xor(input, k, output);

            fixed (byte* s = s_backwardSubstitutionBox,
                t16 = s_lookupTable16,
                t32 = s_lookupTable32,
                t133 = s_lookupTable133,
                t148 = s_lookupTable148,
                t192 = s_lookupTable192,
                t194 = s_lookupTable194,
                t251 = s_lookupTable251)
            {
                for (var i = 8; i >= 0; i--)
                {
                    DoLinearTransformBackward(output, t16, t32, t133, t148, t192, t194, t251);
                    Substitute(s, output);

                    fixed (byte* k = keyExpansion[i])
                        Xor(output, k);
                }
            }
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Copy(byte* source, byte* destination)
        {
            *(ulong*)destination = *(ulong*)source;
            *(((ulong*)destination) + 1) = *(((ulong*)source) + 1);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Xor(byte* left, byte* right, byte* result)
        {
            *(ulong*)result = *(ulong*)left ^ *(ulong*)right;
            *(((ulong*)result) + 1) = *(((ulong*)left) + 1) ^ *(((ulong*)right) + 1);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Xor(byte* result, byte* right)
        {
            *(ulong*)result ^= *(ulong*)right;
            *(((ulong*)result) + 1) ^= *(((ulong*)right) + 1);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Substitute(byte* substTable, byte* data)
        {
            for (var i = 0; i < 16; i++)
                data[i] = substTable[data[i]];
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void DoLinearTransformForward(byte* data, byte* t16, byte* t32, byte* t133, byte* t148, byte* t192, byte* t194, byte* t251)
        {
            data[15] ^= (byte)(data[6] ^ t251[data[7]] ^ data[8] ^
                t148[data[0]] ^ t148[data[14]] ^
                t32[data[1]] ^ t32[data[13]] ^
                t133[data[2]] ^ t133[data[12]] ^
                t16[data[3]] ^ t16[data[11]] ^
                t194[data[4]] ^ t194[data[10]] ^
                t192[data[5]] ^ t192[data[9]]);

            data[14] ^= (byte)(data[5] ^ t251[data[6]] ^ data[7] ^
                t148[data[15]] ^ t148[data[13]] ^
                t32[data[0]] ^ t32[data[12]] ^
                t133[data[1]] ^ t133[data[11]] ^
                t16[data[2]] ^ t16[data[10]] ^
                t194[data[3]] ^ t194[data[9]] ^
                t192[data[4]] ^ t192[data[8]]);

            data[13] ^= (byte)(data[4] ^ t251[data[5]] ^ data[6] ^
                t148[data[14]] ^ t148[data[12]] ^
                t32[data[15]] ^ t32[data[11]] ^
                t133[data[0]] ^ t133[data[10]] ^
                t16[data[1]] ^ t16[data[9]] ^
                t194[data[2]] ^ t194[data[8]] ^
                t192[data[3]] ^ t192[data[7]]);

            data[12] ^= (byte)(data[3] ^ t251[data[4]] ^ data[5] ^
                t148[data[13]] ^ t148[data[11]] ^
                t32[data[14]] ^ t32[data[10]] ^
                t133[data[15]] ^ t133[data[9]] ^
                t16[data[0]] ^ t16[data[8]] ^
                t194[data[1]] ^ t194[data[7]] ^
                t192[data[2]] ^ t192[data[6]]);

            data[11] ^= (byte)(data[2] ^ t251[data[3]] ^ data[4] ^
                t148[data[12]] ^ t148[data[10]] ^
                t32[data[13]] ^ t32[data[9]] ^
                t133[data[14]] ^ t133[data[8]] ^
                t16[data[15]] ^ t16[data[7]] ^
                t194[data[0]] ^ t194[data[6]] ^
                t192[data[1]] ^ t192[data[5]]);

            data[10] ^= (byte)(data[1] ^ t251[data[2]] ^ data[3] ^
                t148[data[11]] ^ t148[data[9]] ^
                t32[data[12]] ^ t32[data[8]] ^
                t133[data[13]] ^ t133[data[7]] ^
                t16[data[14]] ^ t16[data[6]] ^
                t194[data[15]] ^ t194[data[5]] ^
                t192[data[0]] ^ t192[data[4]]);

            data[9] ^= (byte)(data[0] ^ t251[data[1]] ^ data[2] ^
                t148[data[10]] ^ t148[data[8]] ^
                t32[data[11]] ^ t32[data[7]] ^
                t133[data[12]] ^ t133[data[6]] ^
                t16[data[13]] ^ t16[data[5]] ^
                t194[data[14]] ^ t194[data[4]] ^
                t192[data[15]] ^ t192[data[3]]);

            data[8] ^= (byte)(data[15] ^ t251[data[0]] ^ data[1] ^
                t148[data[9]] ^ t148[data[7]] ^
                t32[data[10]] ^ t32[data[6]] ^
                t133[data[11]] ^ t133[data[5]] ^
                t16[data[12]] ^ t16[data[4]] ^
                t194[data[13]] ^ t194[data[3]] ^
                t192[data[14]] ^ t192[data[2]]);

            data[7] ^= (byte)(data[14] ^ t251[data[15]] ^ data[0] ^
                t148[data[8]] ^ t148[data[6]] ^
                t32[data[9]] ^ t32[data[5]] ^
                t133[data[10]] ^ t133[data[4]] ^
                t16[data[11]] ^ t16[data[3]] ^
                t194[data[12]] ^ t194[data[2]] ^
                t192[data[13]] ^ t192[data[1]]);

            data[6] ^= (byte)(data[13] ^ t251[data[14]] ^ data[15] ^
                t148[data[7]] ^ t148[data[5]] ^
                t32[data[8]] ^ t32[data[4]] ^
                t133[data[9]] ^ t133[data[3]] ^
                t16[data[10]] ^ t16[data[2]] ^
                t194[data[11]] ^ t194[data[1]] ^
                t192[data[12]] ^ t192[data[0]]);

            data[5] ^= (byte)(data[12] ^ t251[data[13]] ^ data[14] ^
                t148[data[6]] ^ t148[data[4]] ^
                t32[data[7]] ^ t32[data[3]] ^
                t133[data[8]] ^ t133[data[2]] ^
                t16[data[9]] ^ t16[data[1]] ^
                t194[data[10]] ^ t194[data[0]] ^
                t192[data[11]] ^ t192[data[15]]);

            data[4] ^= (byte)(data[11] ^ t251[data[12]] ^ data[13] ^
                t148[data[5]] ^ t148[data[3]] ^
                t32[data[6]] ^ t32[data[2]] ^
                t133[data[7]] ^ t133[data[1]] ^
                t16[data[8]] ^ t16[data[0]] ^
                t194[data[9]] ^ t194[data[15]] ^
                t192[data[10]] ^ t192[data[14]]);

            data[3] ^= (byte)(data[10] ^ t251[data[11]] ^ data[12] ^
                t148[data[4]] ^ t148[data[2]] ^
                t32[data[5]] ^ t32[data[1]] ^
                t133[data[6]] ^ t133[data[0]] ^
                t16[data[7]] ^ t16[data[15]] ^
                t194[data[8]] ^ t194[data[14]] ^
                t192[data[9]] ^ t192[data[13]]);

            data[2] ^= (byte)(data[9] ^ t251[data[10]] ^ data[11] ^
                t148[data[3]] ^ t148[data[1]] ^
                t32[data[4]] ^ t32[data[0]] ^
                t133[data[5]] ^ t133[data[15]] ^
                t16[data[6]] ^ t16[data[14]] ^
                t194[data[7]] ^ t194[data[13]] ^
                t192[data[8]] ^ t192[data[12]]);

            data[1] ^= (byte)(data[8] ^ t251[data[9]] ^ data[10] ^
                t148[data[2]] ^ t148[data[0]] ^
                t32[data[3]] ^ t32[data[15]] ^
                t133[data[4]] ^ t133[data[14]] ^
                t16[data[5]] ^ t16[data[13]] ^
                t194[data[6]] ^ t194[data[12]] ^
                t192[data[7]] ^ t192[data[11]]);

            data[0] ^= (byte)(data[7] ^ t251[data[8]] ^ data[9] ^
                t148[data[1]] ^ t148[data[15]] ^
                t32[data[2]] ^ t32[data[14]] ^
                t133[data[3]] ^ t133[data[13]] ^
                t16[data[4]] ^ t16[data[12]] ^
                t194[data[5]] ^ t194[data[11]] ^
                t192[data[6]] ^ t192[data[10]]);
        }

        [SecurityCritical]
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void DoLinearTransformBackward(byte* data, byte* t16, byte* t32, byte* t133, byte* t148, byte* t192, byte* t194, byte* t251)
        {
            data[0] ^= (byte)(data[7] ^ t251[data[8]] ^ data[9] ^
                t148[data[1]] ^ t148[data[15]] ^
                t32[data[2]] ^ t32[data[14]] ^
                t133[data[3]] ^ t133[data[13]] ^
                t16[data[4]] ^ t16[data[12]] ^
                t194[data[5]] ^ t194[data[11]] ^
                t192[data[6]] ^ t192[data[10]]);

            data[1] ^= (byte)(data[8] ^ t251[data[9]] ^ data[10] ^
                t148[data[2]] ^ t148[data[0]] ^
                t32[data[3]] ^ t32[data[15]] ^
                t133[data[4]] ^ t133[data[14]] ^
                t16[data[5]] ^ t16[data[13]] ^
                t194[data[6]] ^ t194[data[12]] ^
                t192[data[7]] ^ t192[data[11]]);

            data[2] ^= (byte)(data[9] ^ t251[data[10]] ^ data[11] ^
                t148[data[3]] ^ t148[data[1]] ^
                t32[data[4]] ^ t32[data[0]] ^
                t133[data[5]] ^ t133[data[15]] ^
                t16[data[6]] ^ t16[data[14]] ^
                t194[data[7]] ^ t194[data[13]] ^
                t192[data[8]] ^ t192[data[12]]);

            data[3] ^= (byte)(data[10] ^ t251[data[11]] ^ data[12] ^
                t148[data[4]] ^ t148[data[2]] ^
                t32[data[5]] ^ t32[data[1]] ^
                t133[data[6]] ^ t133[data[0]] ^
                t16[data[7]] ^ t16[data[15]] ^
                t194[data[8]] ^ t194[data[14]] ^
                t192[data[9]] ^ t192[data[13]]);

            data[4] ^= (byte)(data[11] ^ t251[data[12]] ^ data[13] ^
                t148[data[5]] ^ t148[data[3]] ^
                t32[data[6]] ^ t32[data[2]] ^
                t133[data[7]] ^ t133[data[1]] ^
                t16[data[8]] ^ t16[data[0]] ^
                t194[data[9]] ^ t194[data[15]] ^
                t192[data[10]] ^ t192[data[14]]);

            data[5] ^= (byte)(data[12] ^ t251[data[13]] ^ data[14] ^
                t148[data[6]] ^ t148[data[4]] ^
                t32[data[7]] ^ t32[data[3]] ^
                t133[data[8]] ^ t133[data[2]] ^
                t16[data[9]] ^ t16[data[1]] ^
                t194[data[10]] ^ t194[data[0]] ^
                t192[data[11]] ^ t192[data[15]]);

            data[6] ^= (byte)(data[13] ^ t251[data[14]] ^ data[15] ^
                t148[data[7]] ^ t148[data[5]] ^
                t32[data[8]] ^ t32[data[4]] ^
                t133[data[9]] ^ t133[data[3]] ^
                t16[data[10]] ^ t16[data[2]] ^
                t194[data[11]] ^ t194[data[1]] ^
                t192[data[12]] ^ t192[data[0]]);

            data[7] ^= (byte)(data[14] ^ t251[data[15]] ^ data[0] ^
                t148[data[8]] ^ t148[data[6]] ^
                t32[data[9]] ^ t32[data[5]] ^
                t133[data[10]] ^ t133[data[4]] ^
                t16[data[11]] ^ t16[data[3]] ^
                t194[data[12]] ^ t194[data[2]] ^
                t192[data[13]] ^ t192[data[1]]);

            data[8] ^= (byte)(data[15] ^ t251[data[0]] ^ data[1] ^
                t148[data[9]] ^ t148[data[7]] ^
                t32[data[10]] ^ t32[data[6]] ^
                t133[data[11]] ^ t133[data[5]] ^
                t16[data[12]] ^ t16[data[4]] ^
                t194[data[13]] ^ t194[data[3]] ^
                t192[data[14]] ^ t192[data[2]]);

            data[9] ^= (byte)(data[0] ^ t251[data[1]] ^ data[2] ^
                t148[data[10]] ^ t148[data[8]] ^
                t32[data[11]] ^ t32[data[7]] ^
                t133[data[12]] ^ t133[data[6]] ^
                t16[data[13]] ^ t16[data[5]] ^
                t194[data[14]] ^ t194[data[4]] ^
                t192[data[15]] ^ t192[data[3]]);

            data[10] ^= (byte)(data[1] ^ t251[data[2]] ^ data[3] ^
                t148[data[11]] ^ t148[data[9]] ^
                t32[data[12]] ^ t32[data[8]] ^
                t133[data[13]] ^ t133[data[7]] ^
                t16[data[14]] ^ t16[data[6]] ^
                t194[data[15]] ^ t194[data[5]] ^
                t192[data[0]] ^ t192[data[4]]);

            data[11] ^= (byte)(data[2] ^ t251[data[3]] ^ data[4] ^
                t148[data[12]] ^ t148[data[10]] ^
                t32[data[13]] ^ t32[data[9]] ^
                t133[data[14]] ^ t133[data[8]] ^
                t16[data[15]] ^ t16[data[7]] ^
                t194[data[0]] ^ t194[data[6]] ^
                t192[data[1]] ^ t192[data[5]]);

            data[12] ^= (byte)(data[3] ^ t251[data[4]] ^ data[5] ^
                t148[data[13]] ^ t148[data[11]] ^
                t32[data[14]] ^ t32[data[10]] ^
                t133[data[15]] ^ t133[data[9]] ^
                t16[data[0]] ^ t16[data[8]] ^
                t194[data[1]] ^ t194[data[7]] ^
                t192[data[2]] ^ t192[data[6]]);

            data[13] ^= (byte)(data[4] ^ t251[data[5]] ^ data[6] ^
                t148[data[14]] ^ t148[data[12]] ^
                t32[data[15]] ^ t32[data[11]] ^
                t133[data[0]] ^ t133[data[10]] ^
                t16[data[1]] ^ t16[data[9]] ^
                t194[data[2]] ^ t194[data[8]] ^
                t192[data[3]] ^ t192[data[7]]);

            data[14] ^= (byte)(data[5] ^ t251[data[6]] ^ data[7] ^
                t148[data[15]] ^ t148[data[13]] ^
                t32[data[0]] ^ t32[data[12]] ^
                t133[data[1]] ^ t133[data[11]] ^
                t16[data[2]] ^ t16[data[10]] ^
                t194[data[3]] ^ t194[data[9]] ^
                t192[data[4]] ^ t192[data[8]]);

            data[15] ^= (byte)(data[6] ^ t251[data[7]] ^ data[8] ^
                t148[data[0]] ^ t148[data[14]] ^
                t32[data[1]] ^ t32[data[13]] ^
                t133[data[2]] ^ t133[data[12]] ^
                t16[data[3]] ^ t16[data[11]] ^
                t194[data[4]] ^ t194[data[10]] ^
                t192[data[5]] ^ t192[data[9]]);
        }

        [SecuritySafeCritical]
        private static byte[][][] InitializeIterationConstants()
        {
            var retval = new byte[4][][];

            unsafe
            {
                fixed (byte*
                    t16 = s_lookupTable16,
                    t32 = s_lookupTable32,
                    t133 = s_lookupTable133,
                    t148 = s_lookupTable148,
                    t192 = s_lookupTable192,
                    t194 = s_lookupTable194,
                    t251 = s_lookupTable251)
                {
                    for (var i = 0; i < 4; i++)
                    {
                        var row = new byte[8][];

                        for (var j = 0; j < 8; j++)
                        {
                            var iterConst = new byte[16];
                            iterConst[15] = (byte)(i * 8 + j + 1); ;
                            fixed (byte* c = iterConst)
                                DoLinearTransformForward(c, t16, t32, t133, t148, t192, t194, t251);
                            row[j] = iterConst;
                        }

                        retval[i] = row;
                    }
                }
            }

            return retval;
        }

        private static byte[] InitializeLookupTable(byte c)
        {
            var row = new byte[256];
            for (var j = 0; j < 256; j++)
            {
                var x = j;
                var z = 0;
                int y = c;

                while (y != 0)
                {
                    if ((y & 1) != 0)
                        z ^= x;
                    x = x << 1 ^ (((x & 0x80) != 0) ? 0xC3 : 0x00);
                    y >>= 1;
                }

                row[j] = (byte)z;
            }

            return row;
        }
    }
}