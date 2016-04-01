using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static CryptoUtils;

    internal class SymmetricTransformMock : SymmetricTransform
    {
        private byte[] _rgbKey;

        internal SymmetricTransformMock(
            byte[] rgbKey,
            byte[] rgbIV,
            int blockSize,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTransformMode transformMode)
            : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
        { }

        internal bool GenerateKeyExpansionCalled { get; private set; }
        internal bool DisposeCalled { get; private set; }

        protected override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
            => Xor(_rgbKey, 0, inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize); // Simply Xor with key

        protected override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
            => Xor(_rgbKey, 0, inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize); // Simply Xor with key

        protected override void GenerateKeyExpansion(byte[] rgbKey)
        {
            GenerateKeyExpansionCalled = true;

            _rgbKey = (byte[])rgbKey.Clone(); // Simply copy the key
        }

        protected override void Dispose(bool disposing)
        {
            DisposeCalled = true;

            if (_rgbKey != null)
            {
                Array.Clear(_rgbKey, 0, _rgbKey.Length);
                _rgbKey = null;
            }

            base.Dispose(disposing);
        }
    }
}
