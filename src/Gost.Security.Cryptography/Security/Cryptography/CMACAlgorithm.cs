using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static Buffer;
    using static CryptoUtils;

    // Computes Cipher-based Message Authentication Code (CMAC)
    // using any symmetric algorithm
    internal class CMACAlgorithm : KeyedHashAlgorithm
    {
        private readonly SymmetricAlgorithm _symmetricAlgorithm;
        private ICryptoTransform _encryptor;
        private byte[]
            _subkey1,
            _subkey2,
            _buffer,
            _temp,
            _irreduciblePolynomial;

        private readonly int _bytesPerBlock;
        private int _bufferLength;

        public CMACAlgorithm(SymmetricAlgorithm symmetricAlgorithm, byte[] rgbKey, byte[] irreduciblePolynomial)
        {
            if (symmetricAlgorithm == null) throw new ArgumentNullException(nameof(symmetricAlgorithm));
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));
            if (irreduciblePolynomial == null) throw new ArgumentNullException(nameof(irreduciblePolynomial));

            _symmetricAlgorithm = symmetricAlgorithm;

            HashSizeValue = _symmetricAlgorithm.BlockSize;
            KeyValue = (byte[])rgbKey.Clone();

            _bytesPerBlock = HashSizeValue / 8;

            // By definition, the symmetric algorithm takes an IV=0
            _symmetricAlgorithm.IV = new byte[_bytesPerBlock];

            // By definition, special padding (implemented on final hashing)
            _symmetricAlgorithm.Padding = PaddingMode.None;

            _buffer = new byte[_bytesPerBlock];
            _temp = new byte[_bytesPerBlock];
            _irreduciblePolynomial = irreduciblePolynomial;
        }

        public override void Initialize()
        {
            if (_encryptor != null)
            {
                _encryptor.Dispose();
                _encryptor = null;
            }

            EraseData(ref _subkey1);
            EraseData(ref _subkey2);

            _bufferLength = 0;
            Array.Clear(_buffer, 0, _bytesPerBlock);
        }

        protected override void HashCore(byte[] data, int dataOffset, int dataSize)
        {
            EnsureEncryptorInitialized();

            if (_bufferLength > 0 && _bufferLength + dataSize > _bytesPerBlock)
            {
                int bytesToCopy = _bytesPerBlock - _bufferLength;
                BlockCopy(data, dataOffset, _buffer, _bufferLength, bytesToCopy);
                dataOffset += bytesToCopy;
                dataSize -= bytesToCopy;
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _temp, 0);
                _bufferLength = 0;
            }

            if (dataSize >= _bytesPerBlock && _bufferLength == _bytesPerBlock)
            {
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _temp, 0);
                _bufferLength = 0;
            }

            while (dataSize > _bytesPerBlock)
            {
                _encryptor.TransformBlock(data, dataOffset, _bytesPerBlock, _temp, 0);
                dataOffset += _bytesPerBlock;
                dataSize -= _bytesPerBlock;
            }

            if (dataSize > 0)
            {
                BlockCopy(data, dataOffset, _buffer, _bufferLength, dataSize);
                _bufferLength += dataSize;
            }
        }

        protected override byte[] HashFinal()
        {
            EnsureEncryptorInitialized();

            if (_bufferLength == _bytesPerBlock)
                Xor(_buffer, 0, _subkey1, 0, _buffer, 0, _bytesPerBlock);
            else
            {
                // By definition, special padding
                _buffer[_bufferLength] = 0x80;
                Array.Clear(_buffer, _bufferLength, _bytesPerBlock - _bufferLength - 1);

                Xor(_buffer, 0, _subkey2, 0, _buffer, 0, _bytesPerBlock);
            }
            return _encryptor.TransformFinalBlock(_buffer, 0, _bytesPerBlock);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _symmetricAlgorithm.Clear();
                _encryptor?.Dispose();
                EraseData(ref _subkey1);
                EraseData(ref _subkey2);
                EraseData(ref _buffer);
                EraseData(ref _temp);
            }

            base.Dispose(disposing);
        }

        private void EnsureEncryptorInitialized()
        {
            if (_encryptor == null)
            {
                _symmetricAlgorithm.Key = Key;
                _encryptor = _symmetricAlgorithm.CreateEncryptor();
                GenerateSubkeys();
            }
        }

        private void GenerateSubkeys()
        {
            _subkey2 = new byte[_bytesPerBlock];
            _subkey1 = _encryptor.TransformFinalBlock(_subkey2, 0, _bytesPerBlock);
            if (!_encryptor.CanReuseTransform)
            {
                _encryptor.Dispose();
                _encryptor = _symmetricAlgorithm.CreateEncryptor();
            }
            int firstByte = _subkey1[0];

            LeftShiftLittleEndianOneBit(_subkey1);

            if ((firstByte & 0x80) == 0x80)
                Xor(_subkey1, 0, _irreduciblePolynomial, 0, _subkey1, 0, _bytesPerBlock);

            BlockCopy(_subkey1, 0, _subkey2, 0, _bytesPerBlock);

            firstByte = _subkey2[0];

            LeftShiftLittleEndianOneBit(_subkey2);

            if ((firstByte & 0x80) == 0x80)
                Xor(_subkey2, 0, _irreduciblePolynomial, 0, _subkey2, 0, _bytesPerBlock);
        }

        private static void LeftShiftLittleEndianOneBit(byte[] data)
        {
            int lastByte = data.Length - 1;
            for (int i = 0; i < lastByte; i++)
            {
                data[i] <<= 1;
                data[i] |= (byte)((data[i + 1] >> 7) & 0x01);
            }
            data[lastByte] <<= 1;
        }
    }
}