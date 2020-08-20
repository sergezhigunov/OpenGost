using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class CreationFactoriesTests : CryptoConfigRequiredTest
    {
        [Theory]
        [MemberData(nameof(ImplicitCreateFactories))]
        public void ImplicitCreateFactoriesTest(Type expectedType, Func<object> factory)
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
        public void ExplicitCreateFactoriesTest(Type expectedType, Func<string, object> factory, string objectName)
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
            return new[]
            {
                #region Asymmetric algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, CryptoConstants.GostECDsa256AlgorithmName},
                new object[] { typeof(GostECDsa256), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, CryptoConstants.GostECDsa256AlgorithmFullName },
                new object[] { typeof(GostECDsa512), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region Symmetric algorithm factories

                new object[] { typeof(Grasshopper), (Func<string, SymmetricAlgorithm>)SymmetricAlgorithm.Create, CryptoConstants.GrasshopperAlgorithmFullName },
                new object[] { typeof(Magma), (Func<string, SymmetricAlgorithm>)SymmetricAlgorithm.Create, CryptoConstants.MagmaAlgorithmFullName },

                #endregion

                #region Hash algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.CMACMagmaAlgorithmFullName },
                new object[] { typeof(Streebog256), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.Streebog256AlgorithmFullName },
                new object[] { typeof(Streebog512), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.Streebog512AlgorithmFullName },
                new object[] { typeof(HMACStreebog256), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region Keyed hash algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CryptoConstants.CMACMagmaAlgorithmFullName },
                new object[] { typeof(HMACStreebog256), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region HMAC algorithm factories

                new object[] { typeof(HMACStreebog256), (Func<string, HMAC>)HMAC.Create, CryptoConstants.HMACStreebog256AlgorithmFullName },
                new object[] { typeof(HMACStreebog512), (Func<string, HMAC>)HMAC.Create, CryptoConstants.HMACStreebog512AlgorithmFullName },

                #endregion

                #region CMAC algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, CMAC>)CMAC.Create, CryptoConstants.CMACGrasshopperAlgorithmFullName },
                new object[] { typeof(CMACMagma), (Func<string, CMAC>)CMAC.Create, CryptoConstants.CMACMagmaAlgorithmFullName },

                #endregion

                #region GostECDsa algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa>)GostECDsa.Create, CryptoConstants.GostECDsa256AlgorithmName },
                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa>)GostECDsa.Create, CryptoConstants.GostECDsa256AlgorithmFullName },
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa>)GostECDsa.Create, CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa>)GostECDsa.Create, CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa256>)GostECDsa256.Create, CryptoConstants.GostECDsa256AlgorithmName },
                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa256>)GostECDsa256.Create, CryptoConstants.GostECDsa256AlgorithmFullName },

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa512>)GostECDsa512.Create, CryptoConstants.GostECDsa512AlgorithmName },
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa512>)GostECDsa512.Create, CryptoConstants.GostECDsa512AlgorithmFullName },

                #endregion

                #region Grasshopper algorithm factories

                new object[] { typeof(Grasshopper), (Func<string, Grasshopper>)Grasshopper.Create, CryptoConstants.GrasshopperAlgorithmFullName },

                #endregion

                #region Magma algorithm factories

                new object[] { typeof(Magma), (Func<string, Magma>)Magma.Create, CryptoConstants.MagmaAlgorithmFullName },

                #endregion

                #region Streebog256 algorithm factories

                new object[] { typeof(Streebog256), (Func<string, Streebog256>)Streebog256.Create, CryptoConstants.Streebog256AlgorithmFullName },

                #endregion

                #region Streebog512 algorithm factories

                new object[] { typeof(Streebog512), (Func<string, Streebog512>)Streebog512.Create, CryptoConstants.Streebog512AlgorithmFullName },

                #endregion
            };
        }

        public static IEnumerable<object[]> ImplicitCreateFactories()
        {
            return new[]
            {
                new object[] { typeof(CMAC), (Func<CMAC>)CMAC.Create, },
                new object[] { typeof(GostECDsa), (Func<GostECDsa>)GostECDsa.Create, },
                new object[] { typeof(GostECDsa256), (Func<GostECDsa256>)GostECDsa256.Create, },
                new object[] { typeof(GostECDsa512), (Func<GostECDsa512>)GostECDsa512.Create, },
                new object[] { typeof(Grasshopper), (Func<Grasshopper>)Grasshopper.Create, },
                new object[] { typeof(Magma), (Func<Magma>)Magma.Create, },
                new object[] { typeof(Streebog256), (Func<Streebog256>)Streebog256.Create, },
                new object[] { typeof(Streebog512), (Func<Streebog512>)Streebog512.Create, },
            };
        }
    }
}
