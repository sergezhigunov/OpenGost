using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class CreationFactoriesFacts : CryptoConfigRequiredTest
    {
        [Theory]
        [MemberData(nameof(ImplicitCreateFactories))]
        public void CreateImplicit_ReturnsValidInstance(Type expectedType, Func<object> factory)
        {
            var obj = factory.Invoke();
            try
            {
                Assert.NotNull(obj);
                Assert.IsAssignableFrom(expectedType, obj);
            }
            finally
            {
                (obj as IDisposable)?.Dispose();
            }
        }

        [Theory]
        [MemberData(nameof(ExplicitCreateFactories))]
        public void CreateExplicit_ReturnsValidInstance(Type expectedType, Func<string, object> factory, string objectName)
        {
            var obj = factory.Invoke(objectName);
            try
            {
                Assert.NotNull(obj);
                Assert.IsAssignableFrom(expectedType, obj);
            }
            finally
            {
                (obj as IDisposable)?.Dispose();
            }
        }

        public static IEnumerable<object[]> ExplicitCreateFactories()
        {
            static Func<string, T> Func<T>(Func<string, T> func) => func;

            return new[]
            {
                #region Asymmetric algorithm factories

                new object[] { typeof(GostECDsa256), Func(AsymmetricAlgorithm.Create), CryptoConstants.GostECDsa256AlgorithmName},
                new object[] { typeof(GostECDsa256), Func(AsymmetricAlgorithm.Create), CryptoConstants.GostECDsa256AlgorithmFullName },
                new object[] { typeof(GostECDsa512), Func(AsymmetricAlgorithm.Create), CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), Func(AsymmetricAlgorithm.Create), CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region Symmetric algorithm factories

                new object[] { typeof(Grasshopper), Func(SymmetricAlgorithm.Create), CryptoConstants.GrasshopperAlgorithmFullName },
                new object[] { typeof(Magma), Func(SymmetricAlgorithm.Create), CryptoConstants.MagmaAlgorithmFullName },

                #endregion

                #region Hash algorithm factories

                new object[] { typeof(CMACGrasshopper), Func(HashAlgorithm.Create), CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), Func(HashAlgorithm.Create), CryptoConstants.CMACMagmaAlgorithmFullName },
                new object[] { typeof(Streebog256), Func(HashAlgorithm.Create), CryptoConstants.Streebog256AlgorithmFullName },
                new object[] { typeof(Streebog512), Func(HashAlgorithm.Create), CryptoConstants.Streebog512AlgorithmFullName },
                new object[] { typeof(HMACStreebog256), Func(HashAlgorithm.Create), CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), Func(HashAlgorithm.Create), CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region Keyed hash algorithm factories

                new object[] { typeof(CMACGrasshopper), Func(KeyedHashAlgorithm.Create), CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), Func(KeyedHashAlgorithm.Create), CryptoConstants.CMACMagmaAlgorithmFullName },
                new object[] { typeof(HMACStreebog256), Func(KeyedHashAlgorithm.Create), CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), Func(KeyedHashAlgorithm.Create), CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region HMAC algorithm factories

                new object[] { typeof(HMACStreebog256), Func(HMAC.Create), CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), Func(HMAC.Create), CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region CMAC algorithm factories

                new object[] { typeof(CMACGrasshopper), Func(CMAC.Create), CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), Func(CMAC.Create), CryptoConstants.CMACMagmaAlgorithmFullName },

                #endregion

                #region GostECDsa algorithm factories

                new object[] { typeof(GostECDsa256), Func(GostECDsa.Create), CryptoConstants.GostECDsa256AlgorithmName },
                new object[] { typeof(GostECDsa256), Func(GostECDsa.Create), CryptoConstants.GostECDsa256AlgorithmFullName },
                new object[] { typeof(GostECDsa512), Func(GostECDsa.Create), CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), Func(GostECDsa.Create), CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa256), Func(GostECDsa256.Create), CryptoConstants.GostECDsa256AlgorithmName },
                new object[] { typeof(GostECDsa256), Func(GostECDsa256.Create), CryptoConstants.GostECDsa256AlgorithmFullName },

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa512), Func(GostECDsa512.Create), CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), Func(GostECDsa512.Create), CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region Grasshopper algorithm factories

                new object[] { typeof(Grasshopper), Func(Grasshopper.Create), CryptoConstants.GrasshopperAlgorithmFullName },

                #endregion

                #region Magma algorithm factories

                new object[] { typeof(Magma), Func(Magma.Create), CryptoConstants.MagmaAlgorithmFullName },

                #endregion

                #region Streebog256 algorithm factories

                new object[] { typeof(Streebog256), Func(Streebog256.Create), CryptoConstants.Streebog256AlgorithmFullName },

                #endregion

                #region Streebog512 algorithm factories

                new object[] { typeof(Streebog512), Func(Streebog512.Create), CryptoConstants.Streebog512AlgorithmFullName },

                #endregion
            };
        }

        public static IEnumerable<object[]> ImplicitCreateFactories()
        {
            static Func<T> Func<T>(Func<T> func) => func;

            return new[]
            {
                new object[] { typeof(CMACGrasshopper), Func(CMAC.Create), },
                new object[] { typeof(GostECDsa512), Func(GostECDsa.Create), },
                new object[] { typeof(GostECDsa256), Func(GostECDsa256.Create), },
                new object[] { typeof(GostECDsa512), Func(GostECDsa512.Create), },
                new object[] { typeof(Grasshopper), Func(Grasshopper.Create), },
                new object[] { typeof(Magma), Func(Magma.Create), },
                new object[] { typeof(Streebog256), Func(Streebog256.Create), },
                new object[] { typeof(Streebog512), Func(Streebog512.Create), },
            };
        }
    }
}
