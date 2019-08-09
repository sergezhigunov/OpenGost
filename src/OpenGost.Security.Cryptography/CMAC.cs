using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography
{
    using static Buffer;
    using static CryptoConfig;
    using static CryptoConstants;
    using static CryptoUtils;
    using static CryptographyStrings;

    /// <summary>
    /// Represents the abstract class from which implementations of Cipher-based Message Authentication Code
    /// (<see cref="CMAC"/>) can derive.
    /// </summary>
    [ComVisible(true)]
    public abstract class CMAC : KeyedHashAlgorithm
    {
        #region Constants

        private static readonly byte[]
            s_64BitIrreduciblePolynomial =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B
            },
            s_128BitIrreduciblePolynomial =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
            };

        #endregion

        private SymmetricAlgorithm _symmetricAlgorithm;
        private ICryptoTransform _encryptor;
        private byte[]
            _subkey1,
            _subkey2,
            _buffer,
            _temp,
            _irreduciblePolynomial;
        private string _symmetricAlgorithmName;
        private int _bytesPerBlock;
        private int _bufferLength;
        private bool _hashing = false;

        /// <summary>
        /// Gets or sets the key to use in the hash algorithm.
        /// </summary>
        /// <value>
        /// The key to use in the hash algorithm.
        /// </value>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="value"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// An attempt is made to change the <see cref="Key"/> property after hashing has begun. 
        /// </exception>
        public override byte[] Key
        {
            get { return (byte[])KeyValue.Clone(); }
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (_hashing)
                    throw new CryptographicException(CryptographicSymmetricAlgorithmKeySet);

                KeyValue = (byte[])value.Clone();
            }
        }

        /// <summary>
        /// Gets or sets the name of the symmetric algorithm to use for hashing.
        /// </summary>
        /// <value>
        /// The name of the symmetric algorithm.
        /// </value>
        /// <exception cref="ArgumentException">
        /// <paramref name="value"/> is <see langword="null"/> or empty.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The current symmetric algorithm cannot be changed.
        /// -or-
        /// Unknown symmetric algorithm.
        /// -or-
        /// Specified symmetric block size is not valid for this algorithm.
        /// </exception>
        public string SymmetricAlgorithmName
        {
            get { return _symmetricAlgorithmName; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw new ArgumentException(CryptographicSymmetricAlgorithmNameNullOrEmpty, nameof(value));
                if (_hashing)
                    throw new CryptographicException(CryptographicSymmetricAlgorithmNameSet);

                _symmetricAlgorithm = SymmetricAlgorithm.Create(value);

                if (_symmetricAlgorithm == null)
                    throw new CryptographicException(CryptographicUnknownSymmetricAlgorithm(value));

                _symmetricAlgorithmName = value;

                HashSizeValue = _symmetricAlgorithm.BlockSize;

                _irreduciblePolynomial = GetIrreduciblePolynomial(HashSizeValue);

                _bytesPerBlock = HashSizeValue / 8;

                // By definition, the symmetric algorithm takes an IV=0
                _symmetricAlgorithm.IV = new byte[_bytesPerBlock];

                // By definition, special padding (implemented on final hashing)
                _symmetricAlgorithm.Padding = PaddingMode.None;

                _buffer = new byte[_bytesPerBlock];
                _temp = new byte[_bytesPerBlock];
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CMAC"/> class.
        /// </summary>
        protected CMAC()
        { }

        /// <summary>
        /// Initializes an instance of the default implementation of <see cref="CMAC"/>.
        /// </summary>
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
            _hashing = false;
        }

        /// <summary>
        /// Routes data written to the object into the default <see cref="CMAC"/> hash algorithm
        /// for computing the hash value.
        /// </summary>
        /// <param name="array">
        /// The input data.
        /// </param>
        /// <param name="ibStart">
        /// The offset into the byte array from which to begin using data.
        /// </param>
        /// <param name="cbSize">
        /// The number of bytes in the array to use as data. 
        /// </param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            EnsureEncryptorInitialized();

            if (_bufferLength > 0 && _bufferLength + cbSize > _bytesPerBlock)
            {
                var bytesToCopy = _bytesPerBlock - _bufferLength;
                BlockCopy(array, ibStart, _buffer, _bufferLength, bytesToCopy);
                ibStart += bytesToCopy;
                cbSize -= bytesToCopy;
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _temp, 0);
                _bufferLength = 0;
            }

            if (cbSize >= _bytesPerBlock && _bufferLength == _bytesPerBlock)
            {
                _encryptor.TransformBlock(_buffer, 0, _bytesPerBlock, _temp, 0);
                _bufferLength = 0;
            }

            while (cbSize > _bytesPerBlock)
            {
                _encryptor.TransformBlock(array, ibStart, _bytesPerBlock, _temp, 0);
                ibStart += _bytesPerBlock;
                cbSize -= _bytesPerBlock;
            }

            if (cbSize > 0)
            {
                BlockCopy(array, ibStart, _buffer, _bufferLength, cbSize);
                _bufferLength += cbSize;
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code in a byte array.
        /// </returns>
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
            var result = _encryptor.TransformFinalBlock(_buffer, 0, _bytesPerBlock);
            _hashing = false;
            return result;
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="CMAC"/> class when a key change
        /// is legitimate and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources;
        /// <see langword="false"/> to release only unmanaged resources. 
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _symmetricAlgorithm?.Dispose();
                _encryptor?.Dispose();
                EraseData(ref _subkey1);
                EraseData(ref _subkey2);
                EraseData(ref _buffer);
                EraseData(ref _temp);
            }

            base.Dispose(disposing);
        }

        #region Creation factory methods

        /// <summary>
        /// Creates an instance of the default implementation of <see cref="CMAC"/> algorithm.
        /// </summary>
        /// <returns>
        /// A new instance of <see cref="CMAC"/>.
        /// </returns>
        [ComVisible(false)]
        public static new CMAC Create()
            => Create(CMACGrasshopperAlgorithmFullName);

        /// <summary>
        /// Creates an instance of a specified implementation of <see cref="CMAC"/> algorithm.
        /// </summary>
        /// <param name="algorithmName">
        /// The name of the specific implementation of <see cref="CMAC"/> to be used. 
        /// </param>
        /// <returns>
        /// A new instance of <see cref="CMAC"/> using the specified implementation.
        /// </returns>
        [ComVisible(false)]
        public static new CMAC Create(string algorithmName)
            => (CMAC)CreateFromName(algorithmName);

        #endregion

        private void EnsureEncryptorInitialized()
        {
            if (_encryptor == null)
            {
                _hashing = true;
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
            var lastByte = data.Length - 1;
            for (var i = 0; i < lastByte; i++)
            {
                data[i] <<= 1;
                data[i] |= (byte)((data[i + 1] >> 7) & 0x01);
            }
            data[lastByte] <<= 1;
        }

        private static byte[] GetIrreduciblePolynomial(int blockSize)
        {
            switch (blockSize)
            {
                case 64:
                    return s_64BitIrreduciblePolynomial;

                case 128:
                    return s_128BitIrreduciblePolynomial;

                default:
                    throw new CryptographicException(CryptographicInvalidBlockSize);
            }
        }
    }
}
