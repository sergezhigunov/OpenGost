using System;
using System.Security.Cryptography;

namespace Gost.Security.Cryptography
{
    using static Buffer;
    using static CryptoConstants;
    using static CryptoUtils;

    /// <summary>
    /// Computes a Message Authentication Code (MAC) using <see cref="Grasshopper"/> algorithm.
    /// </summary>
    public class MACGrasshopper : KeyedHashAlgorithm
    {
        private readonly Grasshopper _grasshopper;
        private ICryptoTransform _encryptor;
        private byte[]
            _keyExpansion1,
            _keyExpansion2,
            _buffer,
            _state;
        private readonly int _bytesPerBlock;
        private int _bufferLength;

        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class.
        /// </summary>
        public MACGrasshopper()
            : this(GenerateRandomBytes(32))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class with the specified key data.
        /// </summary>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACGrasshopper(byte[] rgbKey)
            : this(GrasshopperManagedAlgorithmFullName, rgbKey)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MACGrasshopper"/> class with the specified key data
        /// and using the specified implementation of <see cref="Grasshopper"/>.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the <see cref="Grasshopper"/> implementation to use. 
        /// </param>
        /// <param name="rgbKey">
        /// The secret key for <see cref="MACGrasshopper"/> encryption. 
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="rgbKey"/> parameter is null. 
        /// </exception>
        public MACGrasshopper(string algorithmName, byte[] rgbKey)
        {
            if (rgbKey == null) throw new ArgumentNullException(nameof(rgbKey));

            _grasshopper =
                algorithmName == null ?
                Grasshopper.Create() :
                Grasshopper.Create(algorithmName);

            HashSizeValue = _grasshopper.BlockSize;
            KeyValue = (byte[])rgbKey.Clone();

            _bytesPerBlock = HashSizeValue / 8;

            // By definition, the Grasshopper algorithm takes an IV=0
            _grasshopper.IV = new byte[_bytesPerBlock];

            // By definition, special padding (implemented on final hashing)
            _grasshopper.Padding = PaddingMode.None;

            _buffer = new byte[_bytesPerBlock];
            _state = new byte[_bytesPerBlock];
        }

        /// <summary>
        /// Initializes an instance of <see cref="MACGrasshopper"/>.
        /// </summary>
        public override void Initialize()
        {
            if (_encryptor != null)
            {
                _encryptor.Dispose();
                _encryptor = null;
            }

            EraseData(ref _keyExpansion1);
            EraseData(ref _keyExpansion2);

            _bufferLength = 0;
            Array.Clear(_buffer, 0, _bytesPerBlock);
            Array.Clear(_state, 0, _bytesPerBlock);
        }

        /// <summary>
        /// Routes data written to the object into the <see cref="Grasshopper"/>
        /// encryptor for computing the Message Authentication Code (MAC).
        /// </summary>
        /// <param name="data">
        /// The input data.
        /// </param>
        /// <param name="dataOffset">
        /// The offset into the byte array from which to begin using data.
        /// </param>
        /// <param name="dataSize">
        /// The number of bytes in the array to use as data.
        /// </param>
        protected override void HashCore(byte[] data, int dataOffset, int dataSize)
        {
            EnsureEncryptorInitialized();

            if (_bufferLength > 0 && _bufferLength + dataSize > _bytesPerBlock)
            {
                int bytesToCopy = _bytesPerBlock - _bufferLength;
                BlockCopy(data, dataOffset, _buffer, _bufferLength, bytesToCopy);
                dataOffset += bytesToCopy;
                dataSize -= bytesToCopy;
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _state, 0);
                _bufferLength = 0;
            }

            if (dataSize >= _bytesPerBlock && _bufferLength == _bytesPerBlock)
            {
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _state, 0);
                _bufferLength = 0;
            }

            while (dataSize > _bytesPerBlock)
            {
                _encryptor.TransformBlock(data, dataOffset, _bytesPerBlock, _state, 0);
                dataOffset += _bytesPerBlock;
                dataSize -= _bytesPerBlock;
            }

            if (dataSize > 0)
            {
                BlockCopy(data, dataOffset, _buffer, _bufferLength, dataSize);
                _bufferLength += dataSize;
            }
        }

        /// <summary>
        /// Returns the computed Message Authentication Code (MAC) after all data is written to the object.
        /// </summary>
        /// <returns>
        /// The computed MAC.
        /// </returns>
        protected override byte[] HashFinal()
        {
            EnsureEncryptorInitialized();

            if (_bufferLength == _bytesPerBlock)
                Xor(_buffer, 0, _keyExpansion1, 0, _buffer, 0, _bytesPerBlock);
            else
            {
                // By definition, special padding
                _buffer[_bufferLength] = 0x80;
                Array.Clear(_buffer, _bufferLength, _bytesPerBlock - _bufferLength - 1);

                Xor(_buffer, 0, _keyExpansion2, 0, _buffer, 0, _bytesPerBlock);
            }
            _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _state, 0);

            return (byte[])_state.Clone();
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="MACGrasshopper"/>
        /// and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// true to release both managed and unmanaged resources;
        /// false to release only unmanaged resources.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _grasshopper.Clear();
                _encryptor?.Dispose();
                EraseData(ref _keyExpansion1);
                EraseData(ref _keyExpansion2);
                EraseData(ref _buffer);
                EraseData(ref _state);
            }

            base.Dispose(disposing);
        }

        private void EnsureEncryptorInitialized()
        {
            if (_encryptor == null)
            {
                _grasshopper.Key = Key;
                _encryptor = _grasshopper.CreateEncryptor();
                GenerateKeyExpansion();
            }
        }

        private void GenerateKeyExpansion()
        {
            _keyExpansion2 = new byte[_bytesPerBlock];
            _keyExpansion1 = _encryptor.TransformFinalBlock(_keyExpansion2, 0, _bytesPerBlock);
            if (!_encryptor.CanReuseTransform)
            {
                _encryptor.Dispose();
                _encryptor = _grasshopper.CreateEncryptor();
            }
            int r0 = _keyExpansion1[0];

            LeftShiftLittleEndianOneBit(_keyExpansion1);

            if ((r0 & 0x80) == 0x80)
                _keyExpansion1[_bytesPerBlock - 1] ^= 0x87;

            BlockCopy(_keyExpansion1, 0, _keyExpansion2, 0, _bytesPerBlock);

            r0 = _keyExpansion2[0];

            LeftShiftLittleEndianOneBit(_keyExpansion2);

            if ((r0 & 0x80) == 0x80)
                _keyExpansion2[_bytesPerBlock - 1] ^= 0x87;
        }
    }
}