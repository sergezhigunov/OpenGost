﻿using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

internal abstract class SymmetricTransform : ICryptoTransform
{
    private readonly bool _encrypting;
    private readonly CipherMode _cipherMode;
    private readonly PaddingMode _paddingMode;

    private byte[] _rgbKey;
    private byte[]? _rgbIV;
    private byte[]? _depadBuffer;
    private byte[]? _stateBuffer;
    private byte[]? _tempBuffer;
    private bool _keyExpanded;

    public bool CanReuseTransform => true;

    public bool CanTransformMultipleBlocks => true;

    public int InputBlockSize { get; }

    public int OutputBlockSize => InputBlockSize;

    protected SymmetricTransform(
        byte[] key,
        byte[]? iv,
        int blockSize,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        bool encrypting)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize),
                CryptographyStrings.ArgumentOutOfRangeNeedPositiveNum);

        _encrypting = encrypting;
        InputBlockSize = blockSize / 8;
        _cipherMode = cipherMode;
        _paddingMode = paddingMode;

        switch (_cipherMode)
        {
            case CipherMode.ECB:
                break;

            case CipherMode.CBC:
            case CipherMode.CFB:
            case CipherMode.OFB:
                ArgumentNullException.ThrowIfNull(iv);
                _rgbIV = (byte[])iv.Clone();
                _stateBuffer = new byte[_rgbIV.Length];
                _tempBuffer = new byte[InputBlockSize];
                Reset();
                break;

            case CipherMode.CTS:
            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);
        }

        _rgbKey = (byte[])key.Clone();
    }

    protected abstract void GenerateKeyExpansion(byte[] key);

    protected abstract void EncryptBlock(
        byte[] inputBuffer,
        int inputOffset,
        byte[] outputBuffer,
        int outputOffset);

    protected abstract void DecryptBlock(byte[] inputBuffer,
        int inputOffset,
        byte[] outputBuffer,
        int outputOffset);

    private void Reset()
    {
        CryptoUtils.EraseData(ref _depadBuffer);

        if (_cipherMode is CipherMode.CBC or CipherMode.CFB or CipherMode.OFB)
        {
            Buffer.BlockCopy(_rgbIV!, 0, _stateBuffer!, 0, _rgbIV!.Length);
        }
    }

    public int TransformBlock(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        byte[] outputBuffer,
        int outputOffset)
    {
        ArgumentNullException.ThrowIfNull(inputBuffer);
        ArgumentNullException.ThrowIfNull(outputBuffer);
        if (inputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset,
                CryptographyStrings.ArgumentOutOfRangeNeedNonNegNum);
        if (outputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(outputOffset), outputOffset,
                CryptographyStrings.ArgumentOutOfRangeNeedNonNegNum);
        if (inputCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(inputCount), inputCount,
                CryptographyStrings.ArgumentOutOfRangeNeedPositiveNum);
        if (inputCount > inputBuffer.Length - inputOffset)
            throw new ArgumentOutOfRangeException(nameof(inputCount), CryptographyStrings.ArgumentInvalidOffLen);
        if (inputCount % InputBlockSize != 0)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidDataSize);

        EnsureKeyExpanded();

        if (_encrypting)
            return EncryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer!, outputOffset, false);
        else
        {
            if (_paddingMode is PaddingMode.Zeros or PaddingMode.None)
                return DecryptData(inputBuffer, inputOffset, inputCount, ref outputBuffer!, outputOffset, false);
            else
            {
                if (_depadBuffer is null)
                {
                    _depadBuffer = new byte[InputBlockSize];
                    // copy the last InputBlockSize bytes to _depadBuffer
                    // everything else gets processed and returned
                    var inputToProcess = inputCount - InputBlockSize;
                    Buffer.BlockCopy(inputBuffer, inputOffset + inputToProcess, _depadBuffer, 0, InputBlockSize);
                    return DecryptData(inputBuffer, inputOffset, inputToProcess, ref outputBuffer!, outputOffset,
                        false);
                }
                else
                {
                    // we already have a depad buffer, so we need to decrypt that info first & copy it out
                    _ = DecryptData(_depadBuffer, 0, _depadBuffer.Length, ref outputBuffer!, outputOffset, false);
                    outputOffset += OutputBlockSize;
                    var inputToProcess = inputCount - InputBlockSize;
                    Buffer.BlockCopy(inputBuffer, inputOffset + inputToProcess, _depadBuffer, 0, InputBlockSize);
                    return OutputBlockSize + DecryptData(inputBuffer, inputOffset, inputToProcess,
                        ref outputBuffer!, outputOffset, false);
                }
            }
        }
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        ArgumentNullException.ThrowIfNull(inputBuffer);
        if (inputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(inputOffset), inputOffset,
                CryptographyStrings.ArgumentOutOfRangeNeedNonNegNum);
        if (inputCount < 0)
            throw new ArgumentOutOfRangeException(nameof(inputCount), inputOffset,
                CryptographyStrings.ArgumentOutOfRangeNeedNonNegNum);
        if (inputCount > inputBuffer.Length - inputOffset)
            throw new ArgumentOutOfRangeException(nameof(inputCount), CryptographyStrings.ArgumentInvalidOffLen);

        EnsureKeyExpanded();

        byte[] transformedBytes = null!;
        if (_encrypting)
            _ = EncryptData(inputBuffer, inputOffset, inputCount, ref transformedBytes!, 0, true);
        else
        {
            if (inputCount % InputBlockSize != 0)
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidDataSize);

            if (_depadBuffer is null)
                _ = DecryptData(inputBuffer, inputOffset, inputCount, ref transformedBytes!, 0, true);
            else
            {
                var temp = new byte[_depadBuffer.Length + inputCount];
                Buffer.BlockCopy(_depadBuffer, 0, temp, 0, _depadBuffer.Length);
                Buffer.BlockCopy(inputBuffer, inputOffset, temp, _depadBuffer.Length, inputCount);
                _ = DecryptData(temp, 0, temp.Length, ref transformedBytes!, 0, true);
            }
        }
        Reset();
        return transformedBytes;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptoUtils.EraseData(ref _rgbKey!);
            CryptoUtils.EraseData(ref _rgbIV);
            CryptoUtils.EraseData(ref _depadBuffer);
            CryptoUtils.EraseData(ref _stateBuffer);
            CryptoUtils.EraseData(ref _tempBuffer);
        }
    }

    private void EnsureKeyExpanded()
    {
        if (!_keyExpanded)
        {
            GenerateKeyExpansion(_rgbKey);
            _keyExpanded = true;
        }
    }

    private int EncryptData(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        ref byte[]? outputBuffer,
        int outputOffset,
        bool isFinalTransform)
    {
        int
            padSize = 0,
            lonelyBytes = inputCount % InputBlockSize;

        byte[]? padBytes = null;

        if (isFinalTransform)
        {
            padBytes = CreatePadding(lonelyBytes);
            if (padBytes != null)
                padSize = padBytes.Length;
        }

        if (outputBuffer is null)
        {
            outputBuffer = new byte[inputCount + padSize];
            outputOffset = 0;
        }
        else if ((outputBuffer.Length - outputOffset) < (inputCount + padSize))
            throw new CryptographicException(CryptographyStrings.CryptographicInsufficientOutputBuffer);

        int shift;
        int boundary = inputCount - lonelyBytes;

        switch (_cipherMode)
        {
            case CipherMode.ECB:
                for (shift = 0; shift < boundary; shift += InputBlockSize)
                    EncryptBlock(inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift);
                break;

            case CipherMode.CBC:
                for (shift = 0; shift < boundary; shift += InputBlockSize)
                {
                    CryptoUtils.Xor(_stateBuffer!, 0, inputBuffer, inputOffset + shift, _tempBuffer!, 0,
                        InputBlockSize);
                    EncryptBlock(_tempBuffer!, 0, outputBuffer, outputOffset + shift);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(outputBuffer, outputOffset + shift, _stateBuffer!,
                        _rgbIV!.Length - InputBlockSize, InputBlockSize);
                }
                break;

            case CipherMode.CFB:
                for (shift = 0; shift < boundary; shift += InputBlockSize)
                {
                    EncryptBlock(_stateBuffer!, 0, _tempBuffer!, 0);
                    CryptoUtils.Xor(_tempBuffer!, 0, inputBuffer, inputOffset + shift, outputBuffer,
                        outputOffset + shift, InputBlockSize);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(outputBuffer, outputOffset + shift, _stateBuffer!,
                        _rgbIV!.Length - InputBlockSize, InputBlockSize);
                }
                break;

            case CipherMode.OFB:
                for (shift = 0; shift < boundary; shift += InputBlockSize)
                {
                    EncryptBlock(_stateBuffer!, 0, _tempBuffer!, 0);
                    CryptoUtils.Xor(_tempBuffer!, 0, inputBuffer, inputOffset + shift, outputBuffer,
                        outputOffset + shift, InputBlockSize);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(_tempBuffer!, 0, _stateBuffer!, _rgbIV!.Length - InputBlockSize,
                        InputBlockSize);
                }
                break;

            case CipherMode.CTS:
            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);
        }

        if (padSize != 0)
            EncryptPaddedBlock(inputBuffer, inputOffset, outputBuffer, outputOffset, padSize, lonelyBytes,
                padBytes!, shift);

        return inputCount + padSize;
    }

    private void EncryptPaddedBlock(
        byte[] inputBuffer,
        int inputOffset,
        byte[] outputBuffer,
        int outputOffset,
        int padSize,
        int lonelyBytes,
        byte[] padBytes,
        int shift)
    {
        byte[] tmpInputBuffer;

        if (padSize == InputBlockSize)
            tmpInputBuffer = padBytes;
        else
        {
            tmpInputBuffer = new byte[InputBlockSize];
            Buffer.BlockCopy(inputBuffer, inputOffset + shift, tmpInputBuffer, 0, lonelyBytes);
            Buffer.BlockCopy(padBytes, 0, tmpInputBuffer, lonelyBytes, padSize);
        }

        switch (_cipherMode)
        {
            case CipherMode.ECB:
                EncryptBlock(tmpInputBuffer, 0, outputBuffer, outputOffset + shift);
                break;

            case CipherMode.CBC:
                CryptoUtils.Xor(_stateBuffer!, 0, tmpInputBuffer, 0, _tempBuffer!, 0, InputBlockSize);
                EncryptBlock(_tempBuffer!, 0, outputBuffer, outputOffset + shift);
                break;

            case CipherMode.CFB:
            case CipherMode.OFB:
                EncryptBlock(_stateBuffer!, 0, _tempBuffer!, 0);
                CryptoUtils.Xor(_tempBuffer!, 0, tmpInputBuffer, 0, outputBuffer, outputOffset + shift,
                    InputBlockSize);
                break;

            case CipherMode.CTS:
            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);
        }
    }

    private byte[]? CreatePadding(int lonelyBytes)
    {
        var padSize = 0;
        byte[]? padBytes = null;

        // check the padding mode and make sure we have enough outputBuffer to handle any padding we have to do
        switch (_paddingMode)
        {
            case PaddingMode.None:
                if (lonelyBytes != 0)
                    throw new CryptographicException(CryptographyStrings.CryptographicInvalidDataSize);
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

            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidPaddingMode);
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
                    for (var index = 0; index < padSize; index++)
                        padBytes[index] = (byte)padSize;
                    break;

                case PaddingMode.ANSIX923:
                    // padBytes is already initialized with zeros. Simply change the last byte
                    padBytes[padSize - 1] = (byte)padSize;
                    break;

                case PaddingMode.ISO10126:
                    // generate random bytes
                    CryptoUtils.StaticRandomNumberGenerator.GetBytes(padBytes);
                    // and change the last byte
                    padBytes[padSize - 1] = (byte)padSize;
                    break;

                default:
                    throw new CryptographicException(CryptographyStrings.CryptographicInvalidPaddingMode);
            }
        }

        return padBytes;
    }

    private int DecryptData(
        byte[] inputBuffer,
        int inputOffset,
        int inputCount,
        ref byte[]? outputBuffer,
        int outputOffset,
        bool isFinalTransform)
    {
        if (outputBuffer is null)
        {
            outputBuffer = new byte[inputCount];
            outputOffset = 0;
        }
        else if ((outputBuffer.Length - outputOffset) < inputCount)
            throw new CryptographicException(CryptographyStrings.CryptographicInsufficientOutputBuffer);

        switch (_cipherMode)
        {
            case CipherMode.ECB:
                for (var shift = 0; shift < inputCount; shift += InputBlockSize)
                    DecryptBlock(inputBuffer, inputOffset + shift, outputBuffer, outputOffset + shift);
                break;

            case CipherMode.CBC:
                for (var shift = 0; shift < inputCount; shift += InputBlockSize)
                {
                    DecryptBlock(inputBuffer, inputOffset + shift, _tempBuffer!, 0);
                    CryptoUtils.Xor(_stateBuffer!, 0, _tempBuffer!, 0, outputBuffer, outputOffset + shift,
                        InputBlockSize);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(inputBuffer, inputOffset + shift, _stateBuffer!,
                        _rgbIV!.Length - InputBlockSize, InputBlockSize);
                }
                break;

            case CipherMode.CFB:
                for (var shift = 0; shift < inputCount; shift += InputBlockSize)
                {
                    EncryptBlock(_stateBuffer!, 0, _tempBuffer!, 0);
                    CryptoUtils.Xor(_tempBuffer!, 0, inputBuffer, inputOffset + shift, outputBuffer,
                        outputOffset + shift, InputBlockSize);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(inputBuffer, inputOffset + shift, _stateBuffer!,
                        _rgbIV!.Length - InputBlockSize, InputBlockSize);
                }
                break;

            case CipherMode.OFB:
                for (var shift = 0; shift < inputCount; shift += InputBlockSize)
                {
                    EncryptBlock(_stateBuffer!, 0, _tempBuffer!, 0);
                    CryptoUtils.Xor(_tempBuffer!, 0, inputBuffer, inputOffset + shift, outputBuffer,
                        outputOffset + shift, InputBlockSize);
                    Buffer.BlockCopy(_stateBuffer!, InputBlockSize, _stateBuffer!, 0,
                        _rgbIV!.Length - InputBlockSize);
                    Buffer.BlockCopy(_tempBuffer!, 0, _stateBuffer!, _rgbIV!.Length - InputBlockSize,
                        InputBlockSize);
                }
                break;

            case CipherMode.CTS:
            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);
        }

        if (!isFinalTransform)
            return inputCount;

        // this is the last block, remove the padding.
        int padSize;
        switch (_paddingMode)
        {
            case PaddingMode.None:
            case PaddingMode.Zeros:
                break;

            case PaddingMode.PKCS7:
                padSize = GetValidPadSize(inputCount, outputBuffer);

                // additional check the validity of the padding
                for (var index = 1; index <= padSize; index++)
                    if (outputBuffer[inputCount - index] != padSize)
                        throw new CryptographicException(CryptographyStrings.CryptographicInvalidPadding);

                RemovePadding(ref outputBuffer, padSize);
                break;

            case PaddingMode.ANSIX923:
                padSize = GetValidPadSize(inputCount, outputBuffer);

                // additional check the validity of the padding
                for (var index = 2; index <= padSize; index++)
                    if (outputBuffer[inputCount - index] != 0)
                        throw new CryptographicException(CryptographyStrings.CryptographicInvalidPadding);

                RemovePadding(ref outputBuffer, padSize);
                break;

            case PaddingMode.ISO10126:
                padSize = GetValidPadSize(inputCount, outputBuffer);
                // no additional check, just ignore the random bytes
                RemovePadding(ref outputBuffer, padSize);
                break;

            default:
                throw new CryptographicException(CryptographyStrings.CryptographicInvalidCipherMode);
        }

        return outputBuffer.Length;
    }

    private int GetValidPadSize(int inputCount, byte[] buffer)
    {
        int padSize;
        if (inputCount == 0)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidPadding);
        padSize = buffer[inputCount - 1];
        if (padSize > buffer.Length || padSize > InputBlockSize || padSize <= 0)
            throw new CryptographicException(CryptographyStrings.CryptographicInvalidPadding);
        return padSize;
    }

    private static void RemovePadding(ref byte[] buffer, int padSize)
    {
        var unpadded = new byte[buffer.Length - padSize];
        Buffer.BlockCopy(buffer, 0, unpadded, 0, buffer.Length - padSize);
        buffer = unpadded;
    }
}
