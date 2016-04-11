using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static Buffer;
    using static SecurityCryptographyStrings;
    using static CryptoUtils;

    internal abstract class SymmetricTransform : ICryptoTransform
    {
        private readonly SymmetricTransformMode _transformMode;
        private readonly CipherMode _cipherMode;
        private readonly PaddingMode _paddingMode;
        private readonly int _blockSize;

        private byte[] _rgbIV;
        private byte[] _depadBuffer;
        private byte[] _stateBuffer;
        private byte[] _tempBuffer;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => _blockSize;

        public int OutputBlockSize => _blockSize;

        protected SymmetricTransform(byte[] rgbKey, byte[] rgbIV, int blockSize, CipherMode cipherMode, PaddingMode paddingMode, SymmetricTransformMode transformMode)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));

            GenerateKeyExpansion(rgbKey);

            _transformMode = transformMode;
            _blockSize = blockSize / 8;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;

            switch (_cipherMode)
            {
                case CipherMode.ECB:
                    break;

                case CipherMode.CBC:
                case CipherMode.CFB:
                case CipherMode.OFB:
                    if (rgbIV == null) throw new ArgumentNullException(nameof(rgbIV));
                    _rgbIV = (byte[])rgbIV.Clone();
                    _stateBuffer = new byte[_rgbIV.Length];
                    _tempBuffer = new byte[_blockSize];
                    Reset();
                    break;

                default:
                    throw new CryptographicException(InvalidCipherMode);
            }
        }

        protected abstract void GenerateKeyExpansion(byte[] rgbKey);

        protected abstract void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset);

        protected abstract void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset);

        private void Reset()
        {
            EraseData(ref _depadBuffer);

            if (_cipherMode == CipherMode.CBC || _cipherMode == CipherMode.CFB || _cipherMode == CipherMode.OFB)
            {
                BlockCopy(_rgbIV, 0, _stateBuffer, 0, _rgbIV.Length);
            }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer == null) throw new ArgumentNullException(nameof(inputBuffer));
            if (outputBuffer == null) throw new ArgumentNullException(nameof(outputBuffer));
            if (inputOffset < 0) throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset, ArgumentOutOfRangeNeedNonNegNum);
            if (outputOffset < 0) throw new ArgumentOutOfRangeException(nameof(outputOffset), outputOffset, ArgumentOutOfRangeNeedNonNegNum);
            if (inputCount <= 0) throw new ArgumentOutOfRangeException(nameof(inputCount), inputCount, ArgumentOutOfRangeNeedPositiveNum);
            if (inputCount % InputBlockSize != 0) throw new ArgumentException(InvalidDataSize, nameof(inputCount));
            if (inputBuffer.Length - inputCount < inputOffset) throw new ArgumentException(ArgumentInvalidOffLen);

            if (_transformMode == SymmetricTransformMode.Encrypt)
                return EncryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, false);
            else
            {
                if (_paddingMode == PaddingMode.Zeros || _paddingMode == PaddingMode.None)
                    return DecryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer, outputOffset, false);
                else
                {
                    if (_depadBuffer == null)
                    {
                        _depadBuffer = new byte[InputBlockSize];
                        // copy the last InputBlockSize bytes to _depadBuffer everything else gets processed and returned
                        int inputToProcess = inputCount - InputBlockSize;
                        BlockCopy(inputBuffer, inputOffset + inputToProcess, _depadBuffer, 0, InputBlockSize);

                        return DecryptData(inputBuffer, inputOffset, inputToProcess, ref outputBuffer, outputOffset, false);
                    }
                    else
                    {
                        // we already have a depad buffer, so we need to decrypt that info first & copy it out
                        DecryptData(_depadBuffer, 0, _depadBuffer.Length, ref outputBuffer, outputOffset, false);
                        outputOffset += OutputBlockSize;
                        int inputToProcess = inputCount - InputBlockSize;
                        BlockCopy(inputBuffer, inputOffset + inputToProcess, _depadBuffer, 0, InputBlockSize);
                        return OutputBlockSize + DecryptData(inputBuffer, inputOffset, inputToProcess, ref outputBuffer, outputOffset, false);
                    }
                }
            }
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null) throw new ArgumentNullException(nameof(inputBuffer));
            if (inputOffset < 0) throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset, ArgumentOutOfRangeNeedNonNegNum);
            if (inputBuffer.Length - inputCount < inputOffset) throw new ArgumentException(ArgumentInvalidOffLen);

            byte[] transformedBytes = null;
            if (_transformMode == SymmetricTransformMode.Encrypt)
                EncryptData(inputBuffer, inputOffset, inputCount, ref transformedBytes, 0, true);
            else
            {
                if (inputCount % InputBlockSize != 0)
                    throw new CryptographicException(InvalidDataSize);

                if (_depadBuffer == null)
                    DecryptData(inputBuffer, inputOffset, inputCount, ref transformedBytes, 0, true);
                else
                {
                    byte[] temp = new byte[_depadBuffer.Length + inputCount];
                    BlockCopy(_depadBuffer, 0, temp, 0, _depadBuffer.Length);
                    BlockCopy(inputBuffer, inputOffset, temp, _depadBuffer.Length, inputCount);
                    DecryptData(temp,
                                0,
                                temp.Length,
                                ref transformedBytes,
                                0,
                                true);
                }
            }
            Reset();
            return transformedBytes;
        }

        public void Dispose()
            => Dispose(true);

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                EraseData(ref _rgbIV);
                EraseData(ref _depadBuffer);
                EraseData(ref _stateBuffer);
                EraseData(ref _tempBuffer);
            }
        }

        private int EncryptData(byte[] inputBuffer, int inputOffset, int inputCount, ref byte[] outputBuffer, int outputOffset, bool isFinalTransform)
        {
            int
                padSize = 0,
                lonelyBytes = inputCount % InputBlockSize;

            // check the padding mode and make sure we have enough outputBuffer to handle any padding we have to do
            byte[] padBytes = null;

            if (isFinalTransform)
            {
                switch (_paddingMode)
                {
                    case PaddingMode.None:
                        if (lonelyBytes != 0)
                            throw new CryptographicException(InvalidDataSize);
                        break;

                    case PaddingMode.Zeros:
                        if (lonelyBytes != 0)
                            padSize = InputBlockSize - lonelyBytes;
                        break;

                    case PaddingMode.PKCS7:
                    case PaddingMode.ANSIX923:
                    case PaddingMode.ISO10126:
                        padSize = InputBlockSize - lonelyBytes;
                        break;
                }

                if (padSize != 0)
                {
                    padBytes = new byte[padSize];

                    switch (_paddingMode)
                    {
                        case PaddingMode.None:
                            break;

                        case PaddingMode.Zeros:
                            // padBytes is already initialized with zeros
                            break;

                        case PaddingMode.PKCS7:
                            for (int index = 0; index < padSize; index++)
                                padBytes[index] = (byte)padSize;
                            break;

                        case PaddingMode.ANSIX923:
                            // padBytes is already initialized with zeros. Simply change the last byte
                            padBytes[padSize - 1] = (byte)padSize;
                            break;

                        case PaddingMode.ISO10126:
                            // generate random bytes
                            StaticRandomNumberGenerator.GetBytes(padBytes);
                            // and change the last byte
                            padBytes[padSize - 1] = (byte)padSize;
                            break;
                    }
                }
            }

            if (outputBuffer == null)
            {
                outputBuffer = new byte[inputCount + padSize];
                outputOffset = 0;
            }
            else if ((outputBuffer.Length - outputOffset) < (inputCount + padSize))
                throw new CryptographicException(InsufficientBuffer);

            int shift;

            switch (_cipherMode)
            {
                case CipherMode.ECB:
                    for (shift = 0; shift < inputCount; shift += InputBlockSize)
                        EncryptBlock(inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift);
                    break;

                case CipherMode.CBC:
                    for (shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        Xor(_stateBuffer, 0, inputBuffer, inputOffset + shift, _tempBuffer, 0, InputBlockSize);
                        EncryptBlock(_tempBuffer, 0, outputBuffer, outputOffset + shift);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(outputBuffer, outputOffset + shift, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                case CipherMode.CFB:
                    for (shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        EncryptBlock(_stateBuffer, 0, _tempBuffer, 0);
                        Xor(_tempBuffer, 0, inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift, InputBlockSize);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(outputBuffer, outputOffset + shift, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                case CipherMode.OFB:
                    for (shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        EncryptBlock(_stateBuffer, 0, _tempBuffer, 0);
                        Xor(_tempBuffer, 0, inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift, InputBlockSize);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(_tempBuffer, 0, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                default:
                    throw new CryptographicException(InvalidCipherMode);
            }

            if (padSize != 0)
            {
                byte[] tmpInputBuffer;

                if (padSize == InputBlockSize)
                    tmpInputBuffer = padBytes;
                else
                {
                    shift -= InputBlockSize;
                    tmpInputBuffer = new byte[InputBlockSize];
                    BlockCopy(inputBuffer, inputOffset + shift, tmpInputBuffer, 0, lonelyBytes);
                    BlockCopy(padBytes, 0, tmpInputBuffer, lonelyBytes, padSize);
                }

                switch (_cipherMode)
                {
                    case CipherMode.ECB:
                        EncryptBlock(tmpInputBuffer, 0, outputBuffer, outputOffset + shift);
                        break;

                    case CipherMode.CBC:
                        Xor(_stateBuffer, 0, tmpInputBuffer, 0, _tempBuffer, 0, InputBlockSize);
                        EncryptBlock(_tempBuffer, 0, outputBuffer, outputOffset + shift);
                        break;

                    case CipherMode.CFB:
                    case CipherMode.OFB:
                        EncryptBlock(_stateBuffer, 0, _tempBuffer, 0);
                        Xor(_tempBuffer, 0, tmpInputBuffer, 0, outputBuffer, outputOffset + shift, InputBlockSize);
                        break;

                    default:
                        throw new CryptographicException(InvalidCipherMode);
                }
            }

            return inputCount + padSize;
        }

        private int DecryptData(byte[] inputBuffer, int inputOffset, int inputCount, ref byte[] outputBuffer, int outputOffset, bool isFinalTransform)
        {
            if (outputBuffer == null)
            {
                outputBuffer = new byte[inputCount];
                outputOffset = 0;
            }
            else if ((outputBuffer.Length - outputOffset) < inputCount)
                throw new CryptographicException(InsufficientBuffer);

            switch (_cipherMode)
            {
                case CipherMode.ECB:
                    for (int shift = 0; shift < inputCount; shift += InputBlockSize)
                        DecryptBlock(inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift);
                    break;

                case CipherMode.CBC:
                    for (int shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        DecryptBlock(inputBuffer, inputOffset + shift, _tempBuffer, 0);
                        Xor(_stateBuffer, 0, _tempBuffer, 0, outputBuffer, outputOffset + shift, InputBlockSize);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(inputBuffer, inputOffset + shift, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                case CipherMode.CFB:
                    for (int shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        EncryptBlock(_stateBuffer, 0, _tempBuffer, 0);
                        Xor(_tempBuffer, 0, inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift, InputBlockSize);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(inputBuffer, inputOffset + shift, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                case CipherMode.OFB:
                    for (int shift = 0; shift < inputCount; shift += InputBlockSize)
                    {
                        EncryptBlock(_stateBuffer, 0, _tempBuffer, 0);
                        Xor(_tempBuffer, 0, inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift, InputBlockSize);
                        BlockCopy(_stateBuffer, InputBlockSize, _stateBuffer, 0, _rgbIV.Length - InputBlockSize);
                        BlockCopy(_tempBuffer, 0, _stateBuffer, _rgbIV.Length - InputBlockSize, InputBlockSize);
                    }
                    break;

                default:
                    throw new CryptographicException(InvalidCipherMode);
            }

            if (!isFinalTransform)
                return inputCount;

            // this is the last block, remove the padding.
            int padSize = 0;

            switch (_paddingMode)
            {
                case PaddingMode.None:
                case PaddingMode.Zeros:
                    break;

                case PaddingMode.PKCS7:
                    padSize = GetValidPadSize(inputCount, outputBuffer);

                    // additional check the validity of the padding
                    for (int index = 1; index <= padSize; index++)
                        if (outputBuffer[inputCount - index] != padSize)
                            throw new CryptographicException(InvalidPadding);

                    RemovePadding(ref outputBuffer, padSize);
                    break;

                case PaddingMode.ANSIX923:
                    padSize = GetValidPadSize(inputCount, outputBuffer);

                    // additional check the validity of the padding
                    for (int index = 2; index <= padSize; index++)
                        if (outputBuffer[inputCount - index] != 0)
                            throw new CryptographicException(InvalidPadding);

                    RemovePadding(ref outputBuffer, padSize);
                    break;

                case PaddingMode.ISO10126:
                    padSize = GetValidPadSize(inputCount, outputBuffer);
                    // no additional check, just ignore the random bytes
                    RemovePadding(ref outputBuffer, padSize);
                    break;
            }

            return outputBuffer.Length;
        }

        private int GetValidPadSize(int inputCount, byte[] buffer)
        {
            int padSize;
            if (inputCount == 0)
                throw new CryptographicException(InvalidPadding);
            padSize = buffer[inputCount - 1];
            if (padSize > buffer.Length || padSize > InputBlockSize || padSize <= 0)
                throw new CryptographicException(InvalidPadding);
            return padSize;
        }

        private static void RemovePadding(ref byte[] buffer, int padSize)
        {
            var unpadded = new byte[buffer.Length - padSize];
            BlockCopy(buffer, 0, unpadded, 0, buffer.Length - padSize);
            buffer = unpadded;
        }
    }
}
