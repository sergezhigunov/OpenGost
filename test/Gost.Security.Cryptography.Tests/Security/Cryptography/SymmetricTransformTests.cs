using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static Buffer;
    using static CryptoUtils;

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

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(CheckLifecycle))]
        public void CheckLifecycle()
        {
            var crossPaddingTransformParameters =
                from p in PaddingModes
                from t in TransformModes
                select new { PaddingMode = p, TransformMode = t };

            var allSupportedParameters =
                from c in SupportedCipherModes
                from pt in crossPaddingTransformParameters
                select new { CipherMode = c, PaddingMode = pt.PaddingMode, TransformMode = pt.TransformMode };

            var reqiresIVParameters =
                from c in CipherModesReqiresIV
                from pt in crossPaddingTransformParameters
                select new { CipherMode = c, PaddingMode = pt.PaddingMode, TransformMode = pt.TransformMode };

            using (var algorithm = new SimpleSymmetricAlgorithm())
            {

                Action<Func<SimpleSymmetricTransform>> checkValid = factory =>
                {
                    var transform = factory();
                    using (transform)
                    {
                        Assert.False(transform.DisposeCalled);
                    }
                    Assert.True(transform.DisposeCalled);
                };

                Action<Type, Func<SimpleSymmetricTransform>> checkInvalid =
                    (expectedExceptionType, factory) => Assert.Throws(expectedExceptionType, factory);

                // All ctor parameters (without CTS)
                foreach (var p in allSupportedParameters)
                    checkValid(() =>
                        new SimpleSymmetricTransform(algorithm.Key, algorithm.IV, algorithm.BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

                // IV is null (ECB)
                foreach (var p in crossPaddingTransformParameters)
                    checkValid(() =>
                        new SimpleSymmetricTransform(algorithm.Key, null, algorithm.BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

                // CTS is invalid
                foreach (var p in crossPaddingTransformParameters)
                    checkInvalid(typeof(CryptographicException), () =>
                        new SimpleSymmetricTransform(algorithm.Key, algorithm.IV, algorithm.BlockSize, CipherMode.CTS, p.PaddingMode, p.TransformMode));

                // Key is null
                foreach (var p in allSupportedParameters)
                    checkInvalid(typeof(ArgumentNullException), () =>
                        new SimpleSymmetricTransform(null, algorithm.IV, algorithm.BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));

                // IV is null (CBC, CFB, OFB)
                foreach (var p in reqiresIVParameters)
                    checkInvalid(typeof(ArgumentNullException), () =>
                        new SimpleSymmetricTransform(algorithm.Key, null, algorithm.BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));
            }
        }

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(EncryptAndDecryptPaddingNone))]
        public void EncryptAndDecryptPaddingNone()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.None })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out cipherText, out newPlainText);
                }

                Assert.Equal(plainText, newPlainText);
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts)
                check(plainText);

            foreach (var plainText in BlockSizeNonMultiplePlainTexts)
                Assert.Throws<CryptographicException>(() => check(plainText));
        }

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(EncryptAndDecryptPaddingZeros))]
        public void EncryptAndDecryptPaddingZeros()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.Zeros })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out cipherText, out newPlainText);
                }

                for (int i = 0; i < plainText.Length; i++)
                Assert.Equal(plainText[i], newPlainText[i]);

            for (int i = plainText.Length; i < newPlainText.Length; i++)
                Assert.Equal(0, newPlainText[i]);
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                check(plainText);
        }

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(EncryptAndDecryptPaddingANSIX923))]
        public void EncryptAndDecryptPaddingANSIX923()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ANSIX923 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                int padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                byte[] padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (int i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (int i = 0; i < padCount - 1; i++)
                        Assert.Equal(0, padding[i]);
                }
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                check(plainText);
        }

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(EncryptAndDecryptPaddingPKCS7))]
        public void EncryptAndDecryptPaddingPKCS7()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                int padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                byte[] padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (int i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (int i = 0; i < padCount - 1; i++)
                        Assert.Equal(padCount, padding[i]);
                }
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                check(plainText);
        }

        [Fact(DisplayName = nameof(SymmetricTransform) + "_" + nameof(EncryptAndDecryptPaddingISO10126))]
        public void EncryptAndDecryptPaddingISO10126()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                using (var algorithm = new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ISO10126 })
                {
                    algorithm.GenerateKey();
                    algorithm.GenerateIV();

                    InternalEncryptAndDecrypt(algorithm, plainText, out cipherText, out newPlainText);

                    algorithm.Padding = PaddingMode.None;

                    newPlainTextNoDepad = InternalTransform(algorithm.CreateDecryptor, cipherText);
                }

                int padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                byte[] padding = new byte[padCount];
                BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (int i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                    Assert.Equal(padCount, padding[padCount - 1]);
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                check(plainText);
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
            using (var transform = factory())
            using (var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, 0, input.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }

        private class SimpleSymmetricAlgorithm : SymmetricAlgorithm
        {
            private static readonly KeySizes[]
                s_legalBlockSizes = { new KeySizes(BlockSizeBits, BlockSizeBits, 0) },
                s_legalKeySizes = { new KeySizes(BlockSizeBits, BlockSizeBits, 0) };

            public SimpleSymmetricAlgorithm()
            {
                KeySizeValue = BlockSizeBits;
                BlockSizeValue = BlockSizeBits;
                FeedbackSizeValue = BlockSizeValue;
                LegalBlockSizesValue = s_legalBlockSizes;
                LegalKeySizesValue = s_legalKeySizes;
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
            {
                if (rgbKey == null)
                    rgbKey = GenerateRandomBytes(KeySizeValue / 8);
                if (rgbIV == null)
                    rgbIV = GenerateRandomBytes(BlockSizeValue / 8);

                return new SimpleSymmetricTransform(rgbKey, rgbIV, BlockSizeValue, ModeValue, PaddingValue, transformMode);
            }
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
