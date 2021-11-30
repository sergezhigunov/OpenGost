using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography;

public class SymmetricTransformFacts
{
    protected const int BlockSizeBits = 64;
    protected const int BlockSizeBytes = BlockSizeBits / 8;

    private static CipherMode[] SupportedCipherModes { get; }
        = { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };

    private static CipherMode[] CipherModesReqiresIV { get; }
        = { CipherMode.CBC, CipherMode.CFB, CipherMode.OFB };

    private static PaddingMode[] PaddingModes { get; }
        = { PaddingMode.None, PaddingMode.Zeros, PaddingMode.ANSIX923, PaddingMode.PKCS7, PaddingMode.ISO10126 };
    private static SymmetricTransformMode[] TransformModes { get; }
        = { SymmetricTransformMode.Encrypt, SymmetricTransformMode.Decrypt };

    private static byte[][] BlockSizeMultiplePlainTexts { get; } =
    {
        CryptoUtils.GenerateRandomBytes(0),
        CryptoUtils.GenerateRandomBytes(BlockSizeBytes),
        CryptoUtils.GenerateRandomBytes(2 * BlockSizeBytes),
        CryptoUtils.GenerateRandomBytes(3 * BlockSizeBytes),
    };

    private static byte[][] BlockSizeNonMultiplePlainTexts { get; } =
    {
        CryptoUtils.GenerateRandomBytes(1),
        CryptoUtils.GenerateRandomBytes(BlockSizeBytes / 2),
        CryptoUtils.GenerateRandomBytes(BlockSizeBytes - 1),
        CryptoUtils.GenerateRandomBytes(BlockSizeBytes + 1),
        CryptoUtils.GenerateRandomBytes(2 * BlockSizeBytes - 2),
        CryptoUtils.GenerateRandomBytes(2 * BlockSizeBytes + 2),
        CryptoUtils.GenerateRandomBytes(3 * BlockSizeBytes - 3),
        CryptoUtils.GenerateRandomBytes(3 * BlockSizeBytes + 3),
    };

    [Fact]
    public void Constructor_Throws_IfParametersAreInvalid()
    {
        var key = new byte[BlockSizeBytes];
        var iv = new byte[BlockSizeBytes];
        var blockSize = BlockSizeBits;

        Assert.Throws<ArgumentNullException>(nameof(key),
            () => new SimpleSymmetricTransform(
                null!,
                iv,
                blockSize,
                CipherMode.ECB,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));

        Assert.Throws<ArgumentOutOfRangeException>(nameof(blockSize),
            () => new SimpleSymmetricTransform(
                key,
                iv,
                0,
                CipherMode.ECB,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));

        Assert.Throws<ArgumentNullException>(nameof(iv),
            () => new SimpleSymmetricTransform(
                key,
                null,
                blockSize,
                CipherMode.CBC,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));

        Assert.Throws<ArgumentNullException>(nameof(iv),
            () => new SimpleSymmetricTransform(
                key,
                null,
                blockSize,
                CipherMode.CFB,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));

        Assert.Throws<ArgumentNullException>(nameof(iv),
            () => new SimpleSymmetricTransform(
                key,
                null,
                blockSize,
                CipherMode.OFB,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));

        Assert.Throws<CryptographicException>(
            () => new SimpleSymmetricTransform(
                key,
                iv,
                blockSize,
                CipherMode.CTS,
                PaddingMode.None,
                SymmetricTransformMode.Encrypt));
    }

    [Fact]
    public void TransformBlock_Throws_IfParametersAreInvalid()
    {
        var inputBuffer = new byte[BlockSizeBytes];
        var outputBuffer = new byte[BlockSizeBytes];
        var inputOffset = 0;
        var inputCount = BlockSizeBytes;
        var outputOffset = 0;
        using var transform = new SimpleSymmetricAlgorithm();
        using var encryptor = transform.CreateEncryptor();

        Assert.Throws<ArgumentNullException>(nameof(inputBuffer),
            () => encryptor.TransformBlock(null!, inputOffset, inputCount, outputBuffer, outputOffset));
        Assert.Throws<ArgumentNullException>(nameof(outputBuffer),
            () => encryptor.TransformBlock(inputBuffer, inputOffset, inputCount, null!, outputOffset));
        Assert.Throws<ArgumentOutOfRangeException>(nameof(inputOffset),
            () => encryptor.TransformBlock(inputBuffer, -1, inputCount, outputBuffer, outputOffset));
        Assert.Throws<ArgumentOutOfRangeException>(nameof(outputOffset),
            () => encryptor.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, -1));
        Assert.Throws<ArgumentOutOfRangeException>(nameof(inputCount),
            () => encryptor.TransformBlock(inputBuffer, inputOffset, 0, outputBuffer, outputOffset));
        Assert.Throws<ArgumentException>(null,
            () => encryptor.TransformBlock(inputBuffer, inputCount, inputCount, outputBuffer, outputOffset));
        Assert.Throws<CryptographicException>(
            () => encryptor.TransformBlock(inputBuffer, inputOffset, inputCount - 1, outputBuffer, outputOffset));
    }

    [Fact]
    public void TransformFinalBlock_Throws_IfParametersAreInvalid()
    {
        var inputBuffer = new byte[BlockSizeBytes];
        var inputCount = BlockSizeBytes;
        var inputOffset = 0;
        using var transform = new SimpleSymmetricAlgorithm();
        using var encryptor = transform.CreateEncryptor();
        using var decryptor = transform.CreateDecryptor();

        Assert.Throws<ArgumentNullException>(nameof(inputBuffer),
            () => encryptor.TransformFinalBlock(null!, inputOffset, inputCount));
        Assert.Throws<ArgumentOutOfRangeException>(nameof(inputOffset),
            () => encryptor.TransformFinalBlock(inputBuffer, -1, inputCount));
        Assert.Throws<ArgumentOutOfRangeException>(nameof(inputCount),
            () => encryptor.TransformFinalBlock(inputBuffer, inputOffset, -1));
        Assert.Throws<ArgumentException>(null,
            () => encryptor.TransformFinalBlock(inputBuffer, inputCount, inputCount));
        Assert.Throws<CryptographicException>(
            () => decryptor.TransformFinalBlock(inputBuffer, inputOffset, inputCount - 1));
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

        static void CheckInvalid(Type expectedExceptionType, Func<SimpleSymmetricTransform> factory)
            => Assert.Throws(expectedExceptionType, factory);

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
                new SimpleSymmetricTransform(null!, algorithm.IV, algorithm.BlockSize, p.CipherMode, p.PaddingMode, p.TransformMode));

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
            using var algorithm =
                new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.None };
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            EncryptAndDecryptUsingCryptoStream(algorithm, plainText, out var cipherText, out var newPlainText);
            Assert.Equal(plainText, newPlainText);
            EncryptAndDecryptUsingTransformFinalBlock(algorithm, plainText, out cipherText, out newPlainText);
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
            using var algorithm =
                new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.Zeros };
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            EncryptAndDecryptUsingCryptoStream(algorithm, plainText, out var cipherText, out var newPlainText);
            AssertEqualIgnoringPaddingZeros(plainText, newPlainText);
            EncryptAndDecryptUsingTransformFinalBlock(algorithm, plainText, out cipherText, out newPlainText);
            AssertEqualIgnoringPaddingZeros(plainText, newPlainText);

            static void AssertEqualIgnoringPaddingZeros(byte[] plainText, byte[] newPlainText)
            {
                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainText[i]);
                for (var i = plainText.Length; i < newPlainText.Length; i++)
                    Assert.Equal(0, newPlainText[i]);
            }
        }

        foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
            Check(plainText);
    }

    [Fact]
    public void EncryptAndDecryptPaddingANSIX923()
    {
        static void Check(byte[] plainText)
        {
            using var algorithm =
                new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ANSIX923 };
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            EncryptAndDecryptUsingCryptoStream(algorithm, plainText, out var cipherText, out var newPlainText);
            AssertEqualWithANSIX923Checks(algorithm, plainText, cipherText, newPlainText);
            EncryptAndDecryptUsingTransformFinalBlock(algorithm, plainText, out cipherText, out newPlainText);
            AssertEqualWithANSIX923Checks(algorithm, plainText, cipherText, newPlainText);

            static void AssertEqualWithANSIX923Checks(
                SimpleSymmetricAlgorithm algorithm,
                byte[] plainText,
                byte[] cipherText,
                byte[] newPlainText)
            {
                var backingPadding = algorithm.Padding;
                algorithm.Padding = PaddingMode.None;
                var newPlainTextNoDepad = TransformUsingCryptoStream(algorithm.CreateDecryptor, cipherText);
                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                Buffer.BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (var i = 0; i < padCount - 1; i++)
                        Assert.Equal(0, padding[i]);
                }
                algorithm.Padding = backingPadding;
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
            using var algorithm =
                new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 };
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            EncryptAndDecryptUsingCryptoStream(algorithm, plainText, out var cipherText, out var newPlainText);
            AssertEqualWithPKCS7Checks(algorithm, plainText, cipherText, newPlainText);
            EncryptAndDecryptUsingTransformFinalBlock(algorithm, plainText, out cipherText, out newPlainText);
            AssertEqualWithPKCS7Checks(algorithm, plainText, cipherText, newPlainText);

            static void AssertEqualWithPKCS7Checks(
                SimpleSymmetricAlgorithm algorithm,
                byte[] plainText,
                byte[] cipherText,
                byte[] newPlainText)
            {
                var backingPadding = algorithm.Padding;
                algorithm.Padding = PaddingMode.None;
                var newPlainTextNoDepad = TransformUsingCryptoStream(algorithm.CreateDecryptor, cipherText);
                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                Buffer.BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                {
                    Assert.Equal(padCount, padding[padCount - 1]);

                    for (var i = 0; i < padCount - 1; i++)
                        Assert.Equal(padCount, padding[i]);
                }
                algorithm.Padding = backingPadding;
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
            using var algorithm =
                new SimpleSymmetricAlgorithm { Mode = CipherMode.ECB, Padding = PaddingMode.ISO10126 };
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            EncryptAndDecryptUsingCryptoStream(algorithm, plainText, out var cipherText, out var newPlainText);
            AssertEqualWithISO10126Checks(algorithm, plainText, cipherText, newPlainText);
            EncryptAndDecryptUsingTransformFinalBlock(algorithm, plainText, out cipherText, out newPlainText);
            AssertEqualWithISO10126Checks(algorithm, plainText, cipherText, newPlainText);

            static void AssertEqualWithISO10126Checks(
                SimpleSymmetricAlgorithm algorithm,
                byte[] plainText,
                byte[] cipherText,
                byte[] newPlainText)
            {
                var backingPadding = algorithm.Padding;
                algorithm.Padding = PaddingMode.None;

                var newPlainTextNoDepad = TransformUsingCryptoStream(algorithm.CreateDecryptor, cipherText);
                var padCount = newPlainTextNoDepad.Length - newPlainText.Length;

                var padding = new byte[padCount];
                Buffer.BlockCopy(newPlainTextNoDepad, newPlainText.Length, padding, 0, padCount);

                Assert.Equal(plainText, newPlainText);

                for (var i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], newPlainTextNoDepad[i]);

                if (padCount > 0)
                    Assert.Equal(padCount, padding[padCount - 1]);
                algorithm.Padding = backingPadding;
            }

        }

        foreach (var plainText in BlockSizeMultiplePlainTexts.Union(BlockSizeNonMultiplePlainTexts))
            Check(plainText);
    }

    private static void EncryptAndDecryptUsingCryptoStream(
        SymmetricAlgorithm algorithm,
        byte[] plainText,
        out byte[] cipherText,
        out byte[] newPlainText)
    {
        cipherText = TransformUsingCryptoStream(algorithm.CreateEncryptor, plainText);
        newPlainText = TransformUsingCryptoStream(algorithm.CreateDecryptor, cipherText);
    }

    private static void EncryptAndDecryptUsingTransformFinalBlock(
        SymmetricAlgorithm algorithm,
        byte[] plainText,
        out byte[] cipherText,
        out byte[] newPlainText)
    {
        cipherText = TransformUsingTransformFinalBlock(algorithm.CreateEncryptor, plainText);
        newPlainText = TransformUsingTransformFinalBlock(algorithm.CreateDecryptor, cipherText);
    }

    private static byte[] TransformUsingCryptoStream(Func<ICryptoTransform> factory, byte[] input)
    {
        var memoryStream = new MemoryStream();
        using var transform = factory();
        using var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
        cryptoStream.Write(input, 0, input.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }

    private static byte[] TransformUsingTransformFinalBlock(Func<ICryptoTransform> factory, byte[] input)
    {
        using var transform = factory();
        return transform.TransformFinalBlock(input, 0, input.Length);
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

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
            => CreateTransform(rgbKey, rgbIV, SymmetricTransformMode.Decrypt);

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
            => CreateTransform(rgbKey, rgbIV, SymmetricTransformMode.Encrypt);

        public override void GenerateIV()
        {
            IVValue = CryptoUtils.GenerateRandomBytes(BlockSizeValue / 8);
        }

        public override void GenerateKey()
        {
            KeyValue = CryptoUtils.GenerateRandomBytes(KeySizeValue / 8);
        }

        private ICryptoTransform CreateTransform(byte[] rgbKey, byte[]? rgbIV, SymmetricTransformMode transformMode)
            => new SimpleSymmetricTransform(rgbKey, rgbIV, BlockSizeValue, ModeValue, PaddingValue, transformMode);
    }

    private class SimpleSymmetricTransform : SymmetricTransform
    {
        private byte[] _rgbKey = null!;

        internal SimpleSymmetricTransform(
            byte[] rgbKey,
            byte[]? rgbIV,
            int blockSize,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            SymmetricTransformMode transformMode)
            : base(rgbKey, rgbIV, blockSize, cipherMode, paddingMode, transformMode)
        { }

        private bool GenerateKeyExpansionCalled { get; set; }

        internal bool DisposeCalled { get; private set; }

        protected override void DecryptBlock(
            byte[] inputBuffer,
            int inputOffset,
            byte[] outputBuffer,
            int outputOffset)
        {
            Assert.True(GenerateKeyExpansionCalled);
            // Simply Xor with key
            for (var i = 0; i < InputBlockSize; i++)
                outputBuffer[outputOffset + i] = (byte)(_rgbKey[i] ^ inputBuffer[inputOffset + i]);
        }

        protected override void EncryptBlock(
            byte[] inputBuffer,
            int inputOffset,
            byte[] outputBuffer,
            int outputOffset)
        {
            Assert.True(GenerateKeyExpansionCalled);
            // Simply Xor with key
            for (var i = 0; i < InputBlockSize; i++)
                outputBuffer[outputOffset + i] = (byte)(_rgbKey[i] ^ inputBuffer[inputOffset + i]);

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
                _rgbKey = null!;
            }

            base.Dispose(disposing);
        }
    }
}
