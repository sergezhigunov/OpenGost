using System;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Gost.Security.Cryptography
{
    using static Buffer;
    using static CryptoUtils;
    using static TestsUtils;

    public class SymmetricTransformTests
    {
        private const int BlockSize = 64;
        private const int KeySize = BlockSize;
        private const int FeedbackSize = BlockSize;
        private const int BlockSizeBytes = BlockSize / 8;
        private const int KeySizeBytes = KeySize / 8;
        private const int FeedbackSizeBytes = FeedbackSize / 8;

        private static CipherMode[] SupportedCipherModes { get; } = { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };
        private static CipherMode[] CipherModesReqiresIV { get; } = { CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };
        private static PaddingMode[] PaddingModes { get; } = { PaddingMode.None, PaddingMode.Zeros, PaddingMode.ANSIX923, PaddingMode.PKCS7, PaddingMode.ISO10126 };
        private static SymmetricTransformMode[] TransformModes { get; } = { SymmetricTransformMode.Encrypt, SymmetricTransformMode.Decrypt };
        private static byte[] Key { get; } = GenerateRandomBytes(KeySize);
        private static byte[] IV { get; } = GenerateRandomBytes(FeedbackSize);

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

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(CheckLifecycle))]
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


            Action<Func<SymmetricTransformMock>> checkValid = factory =>
            {
                var transform = factory();
                using (transform)
                {
                    Assert.True(transform.GenerateKeyExpansionCalled);
                    Assert.False(transform.DisposeCalled);
                }
                Assert.True(transform.DisposeCalled);
            };

            Action<Type, Func<SymmetricTransformMock>> checkInvalid =
                (expectedExceptionType, factory) => Assert.Throws(expectedExceptionType, factory);

            // All ctor parameters (without CTS)
            foreach (var p in allSupportedParameters)
                checkValid(() =>
                    new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

            // IV is null (ECB)
            foreach (var p in crossPaddingTransformParameters)
                checkValid(() =>
                    new SymmetricTransformMock(Key, null, BlockSize, CipherMode.ECB, p.PaddingMode, p.TransformMode));

            // CTS is invalid
            foreach (var p in crossPaddingTransformParameters)
                checkInvalid(typeof(CryptographicException), () =>
                    new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.CTS, p.PaddingMode, p.TransformMode));

            // Key is null
            foreach (var p in allSupportedParameters)
                checkInvalid(typeof(ArgumentNullException), () =>
                    new SymmetricTransformMock(null, IV, BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));

            // IV is null (CBC, CFB, OFB)
            foreach (var p in reqiresIVParameters)
                checkInvalid(typeof(ArgumentNullException), () =>
                    new SymmetricTransformMock(Key, null, BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));
        }

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(EncryptAndDecryptPaddingNone))]
        public void EncryptAndDecryptPaddingNone()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText;

                InternalEncryptAndDecrypt(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Encrypt),
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Decrypt),
                    plainText, out cipherText, out newPlainText);

                Assert.Equal(plainText, newPlainText);

            };

            foreach (var plainText in BlockSizeMultiplePlainTexts)
                check(plainText);

            foreach (var plainText in BlockSizeNonMultiplePlainTexts)
                Assert.Throws<CryptographicException>(() => check(plainText));
        }

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(EncryptAndDecryptPaddingZeros))]
        public void EncryptAndDecryptPaddingZeros()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText;

                InternalEncryptAndDecrypt(
                () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.Zeros, SymmetricTransformMode.Encrypt),
                () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.Zeros, SymmetricTransformMode.Decrypt),
                plainText, out cipherText, out newPlainText);

            for (int i = 0; i < plainText.Length; i++)
                Assert.Equal(plainText[i], newPlainText[i]);

            for (int i = plainText.Length; i < newPlainText.Length; i++)
                Assert.Equal(0, newPlainText[i]);
            };

            foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
                check(plainText);
        }

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(EncryptAndDecryptPaddingANSIX923))]
        public void EncryptAndDecryptPaddingANSIX923()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                InternalEncryptAndDecrypt(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.ANSIX923, SymmetricTransformMode.Encrypt),
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.ANSIX923, SymmetricTransformMode.Decrypt),
                    plainText, out cipherText, out newPlainText);

                newPlainTextNoDepad = InternalTransform(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Decrypt),
                    cipherText);

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

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(EncryptAndDecryptPaddingPKCS7))]
        public void EncryptAndDecryptPaddingPKCS7()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                InternalEncryptAndDecrypt(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.PKCS7, SymmetricTransformMode.Encrypt),
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.PKCS7, SymmetricTransformMode.Decrypt),
                    plainText, out cipherText, out newPlainText);

                newPlainTextNoDepad = InternalTransform(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Decrypt),
                    cipherText);

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

        [Fact(DisplayName = nameof(SymmetricTransformTests) + "_" + nameof(EncryptAndDecryptPaddingISO10126))]
        public void EncryptAndDecryptPaddingISO10126()
        {
            Action<byte[]> check = plainText =>
            {
                byte[] cipherText, newPlainText, newPlainTextNoDepad;

                InternalEncryptAndDecrypt(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.ISO10126, SymmetricTransformMode.Encrypt),
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.ISO10126, SymmetricTransformMode.Decrypt),
                    plainText, out cipherText, out newPlainText);

                newPlainTextNoDepad = InternalTransform(
                    () => new SymmetricTransformMock(Key, IV, BlockSize, CipherMode.ECB, PaddingMode.None, SymmetricTransformMode.Decrypt),
                    cipherText);

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
    }
}
