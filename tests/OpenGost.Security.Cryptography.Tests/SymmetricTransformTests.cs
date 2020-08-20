using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;
using static System.Buffer;
using static OpenGost.Security.Cryptography.CryptoUtils;

namespace OpenGost.Security.Cryptography
{
    public class SymmetricTransformTests
    {
        protected const int BlockSizeBits = 64;
        protected const int BlockSizeBytes = BlockSizeBits / 8;

        private static CipherMode[] SupportedCipherModes { get; } = { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };
        private static CipherMode[] CipherModesReqiresIV { get; } = { CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };
        private static PaddingMode[] PaddingModes { get; } = { PaddingMode.None, PaddingMode.Zeros, PaddingMode.ANSIX923, PaddingMode.PKCS7, PaddingMode.ISO10126 };
        private static SymmetricTransformMode[] TransformModes { get; } = { SymmetricTransformMode.Encrypt, SymmetricTransformMode.Decrypt };

        private static byte[][] BlockSizeMultiplePlainTexts { get; } =
        {
            GenerateRandomBytes(0),
            GenerateRandomBytes(BlockSizeBytes),
            GenerateRandomBytes(2 * BlockSizeBytes),
            GenerateRandomBytes(3 * BlockSizeBytes),
        };

        private static byte[][] BlockSizeNonMultiplePlainTexts { get; } =
        {
            GenerateRandomBytes(1),
            GenerateRandomBytes(BlockSizeBytes / 2),
            GenerateRandomBytes(BlockSizeBytes - 1),
            GenerateRandomBytes(BlockSizeBytes + 1),
            GenerateRandomBytes(2 * BlockSizeBytes - 2),
            GenerateRandomBytes(2 * BlockSizeBytes + 2),
            GenerateRandomBytes(3 * BlockSizeBytes - 3),
            GenerateRandomBytes(3 * BlockSizeBytes + 3),
        };

        [Fact]
        public void ConstructorInvalidArgumentsTest()
        {
            Assert.Throws<ArgumentNullException>(() => new SimpleSymmetricTransform(null, new byte[BlockSizeBytes], BlockSizeBits, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Encrypt));
            Assert.Throws<ArgumentOutOfRangeException>(() => new SimpleSymmetricTransform(new byte[BlockSizeBytes], new byte[BlockSizeBytes], 0, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Encrypt));
            Assert.Throws<ArgumentNullException>(() => new SimpleSymmetricTransform(new byte[BlockSizeBytes], null, BlockSizeBytes, CipherMode.CBC, PaddingMode.None, SymmetricTransformMode.Encrypt));
            Assert.Throws<ArgumentNullException>(() => new SimpleSymmetricTransform(new byte[BlockSizeBytes], null, BlockSizeBytes, CipherMode.CFB, PaddingMode.None, SymmetricTransformMode.Encrypt));
            Assert.Throws<ArgumentNullException>(() => new SimpleSymmetricTransform(new byte[BlockSizeBytes], null, BlockSizeBytes, CipherMode.OFB, PaddingMode.None, SymmetricTransformMode.Encrypt));
            Assert.Throws<CryptographicException>(() => new SimpleSymmetricTransform(new byte[BlockSizeBytes], new byte[BlockSizeBytes], BlockSizeBytes, CipherMode.CTS, PaddingMode.None, SymmetricTransformMode.Encrypt));
        }

        [Fact]
        public void TransformBlockInvalidArgumentsTest()
        {
            using var transform = new SimpleSymmetricAlgorithm();
            using var encryptor = transform.CreateEncryptor();
            Assert.Throws<ArgumentNullException>(() => encryptor.TransformBlock(null, 0, BlockSizeBytes, new byte[BlockSizeBytes], 0));
            Assert.Throws<ArgumentNullException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], 0, BlockSizeBytes, null, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], -1, BlockSizeBytes, new byte[BlockSizeBytes], 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], 0, BlockSizeBytes, new byte[BlockSizeBytes], -1));
            Assert.Throws<ArgumentOutOfRangeException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], 0, 0, new byte[BlockSizeBytes], 0));
            Assert.Throws<ArgumentException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], BlockSizeBytes, BlockSizeBytes, new byte[BlockSizeBytes], 0));
            Assert.Throws<CryptographicException>(() => encryptor.TransformBlock(new byte[BlockSizeBytes], 0, BlockSizeBytes - 1, new byte[BlockSizeBytes], 0));
        }

        [Fact]
        public void TransformFinalBlockInvalidArgumentsTest()
        {
            using var transform = new SimpleSymmetricAlgorithm();
            using (var encryptor = transform.CreateDecryptor())
            {
                Assert.Throws<ArgumentNullException>(() => encryptor.TransformFinalBlock(null, 0, BlockSizeBytes));
                Assert.Throws<ArgumentOutOfRangeException>(() => encryptor.TransformFinalBlock(new byte[BlockSizeBytes], -1, BlockSizeBytes));
                Assert.Throws<ArgumentOutOfRangeException>(() => encryptor.TransformFinalBlock(new byte[BlockSizeBytes], 0, -1));
                Assert.Throws<ArgumentException>(() => encryptor.TransformFinalBlock(new byte[BlockSizeBytes], BlockSizeBytes, BlockSizeBytes));
            }
            using var decryptor = transform.CreateDecryptor();
            Assert.Throws<CryptographicException>(() => decryptor.TransformFinalBlock(new byte[BlockSizeBytes], 0, BlockSizeBytes - 1));
        }

        [Fact]
        public void CheckLifecycle()
        {
            var crossPaddingTransformParameters =
                from p in PaddingModes
                from t in TransformModes
                select new { PaddingMode = p, TransformMode = t };

            var allSupportedParameters =
                from c in SupportedCipherModes
                from pt in crossPaddingTransformParameters
                select new { CipherMode = c, pt.PaddingMode, pt.TransformMode };

            var reqiresIVParameters =
                from c in CipherModesReqiresIV
                from pt in crossPaddingTransformParameters
                select new { CipherMode = c, pt.PaddingMode, pt.TransformMode };

            using var algorithm = new SimpleSymmetricAlgorithm();

            static void CheckValid(Func<SimpleSymmetricTransform> factory)
            {
                var transform = factory();
                using (transform)
                {
                    Assert.False(transform.DisposeCalled);
                }
                Assert.True(transform.DisposeCalled);
            }

            static void CheckInvalid(Type expectedExceptionType, Func<SimpleSymmetricTransform> factory) => Assert.Throws(expectedExceptionType, factory);

            // All ctor parameters (without CTS)
            foreach (var p in allSupportedParameters)
                CheckValid(() =>
                    new SimpleSymmetricTransform(algorithm.Key, algorithm.IV, algorithm.BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

            // IV is null (ECB)
            foreach (var p in crossPaddingTransformParameters)
                CheckValid(() =>
                    new SimpleSymmetricTransform(algorithm.Key, null, algorithm.BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

            // CTS is invalid
            foreach (var p in crossPaddingTransformParameters)
                CheckInvalid(typeof(CryptographicException), () =>
                    new SimpleSymmetricTransform(algorithm.Key, algorithm.IV, algorithm.BlockSize, CipherMode.CTS, p.PaddingMode, p.TransformMode));

            // Key is null
            foreach (var p in allSupportedParameters)
                CheckInvalid(typeof(ArgumentNullException), () =>
                    new SimpleSymmetricTransform(null, algorithm.IV, algorithm.BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));

            // IV is null (CBC, CFB, OFB)
            foreach (var p in reqiresIVParameters)
                CheckInvalid(typeof(ArgumentNullException), () =>
                    new SimpleSymmetricTransform(algorithm.Key, null, algorithm.BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));
        }

        [Fact]
        public void EncryptAndDecryptPaddingNone()
        {
            static void Check(byte[] plainText)
            {
                byte[] newPlainText;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.None })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out var cipherText, out newPlainText);
                }

                Assert.Equal(plainText, newPlainText);
            }

            foreach (var plainText in BlockSizeMultiplePlainTexts)
                Check(plainText);

            foreach (var plainText in BlockSizeNonMultiplePlainTexts)
                Assert.Throws<CryptographicException>(() => Check(plainText));
        }

        [Fact]
        public void EncryptAndDecryptPaddingZeros()
        {
            static void Check(byte[] plainText)
            {
                byte[] newPlainText;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.Zeros })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out var cipherText, out newPlainText);
                }

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainText[i]);

                for (var i = plainText.Length; i < newPlainText.Length; i++)
                    Assert.Equal(0, newPlainText[i]);
            }

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                Check(plainText);
        }

        [Fact]
        public void EncryptAndDecryptPaddingANSIX923()
        {
            static void Check(byte[] plainText)
            {
                byte[] newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ANSIX923 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out var cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (var i = 0; i < padCount - 1; i++)
                        Assert.Equal(0, padding[i]);
                }
            }

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                Check(plainText);
        }

        [Fact]
        public void EncryptAndDecryptPaddingPKCS7()
        {
            static void Check(byte[] plainText)
            {
                byte[] newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out var cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (var i = 0; i < padCount - 1; i++)
                        Assert.Equal(padCount, padding[i]);
                }
            }

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                Check(plainText);
        }

        [Fact]
        public void EncryptAndDecryptPaddingISO10126()
        {
            static void Check(byte[] plainText)
            {
                byte[] newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ISO10126 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out var cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                    Assert.Equal(padCount, padding[padCount - 1]);
            }

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                Check(plainText);
        }

        private static void InternalEncryptAndDecrypt(
            SymmetricAlgorithm algorithm,
            byte[] plainText,
            out byte[] cipherText,
            out byte[] newPlainText)
        {
            cipherText = InternalTransform(algorithm.CreateEncryptor, plainText);
            newPlainText = InternalTransform(algorithm.CreateDecryptor, cipherText);
        }

        private static byte[] InternalTransform(Func<ICryptoTransform> factory, byte[] input)
        {
            var memoryStream = new MemoryStream();
            using var transform = factory();
            using var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
            cryptoStream.Write(input, 0, input.Length);
            cryptoStream.FlushFinalBlock();
            return memoryStream.ToArray();
        }

        private class SimpleSymmetricAlgorithm : SymmetricAlgorithm
        {
            private static readonly KeySizes[]
                _legalBlockSizes = { new KeySizes(BlockSizeBits, BlockSizeBits, 0) },
                _legalKeySizes = { new KeySizes(BlockSizeBits, BlockSizeBits, 0) };

            public SimpleSymmetricAlgorithm()
            {
                KeySizeValue = BlockSizeBits;
                BlockSizeValue = BlockSizeBits;
                FeedbackSizeValue = BlockSizeValue;
                LegalBlockSizesValue = _legalBlockSizes;
                LegalKeySizesValue = _legalKeySizes;
            }

            public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
                => CreateTransform(rgbKey, rgbIV, SymmetricTransformMode.Decrypt);

            public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
                => CreateTransform(rgbKey, rgbIV, SymmetricTransformMode.Encrypt);

            public override void GenerateIV()
            {
                IVValue = GenerateRandomBytes(BlockSizeValue / 8);
            }

            public override void GenerateKey()
            {
                KeyValue = GenerateRandomBytes(KeySizeValue / 8);
            }

            private ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV, SymmetricTransformMode transformMode)
                => new SimpleSymmetricTransform(rgbKey, rgbIV, BlockSizeValue, ModeValue, PaddingValue, transformMode);
        }

        private class SimpleSymmetricTransform : SymmetricTransform
        {
            private byte[] _rgbKey;

            internal SimpleSymmetricTransform(
                byte[] rgbKey,
                byte[] rgbIV,
                int blockSize,
                CipherMode cipherMode,
                PaddingMode paddingMode,
                SymmetricTransformMode transformMode)
                : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
            { }

            private bool GenerateKeyExpansionCalled { get; set; }

            internal bool DisposeCalled { get; private set; }

            protected override void DecryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
            {
                Assert.True(GenerateKeyExpansionCalled);
                Xor(_rgbKey, 0, inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize); // Simply Xor with key
            }

            protected override void EncryptBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
            {
                Assert.True(GenerateKeyExpansionCalled);
                Xor(_rgbKey, 0, inputBuffer, inputOffset, outputBuffer, outputOffset, InputBlockSize); // Simply Xor with key
            }

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
}
