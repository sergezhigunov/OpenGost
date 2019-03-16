using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    using static CryptoConstants;

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
                if (obj is IDisposable)
                    ((IDisposable)obj).Dispose();
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
                if (obj is IDisposable)
                    ((IDisposable)obj).Dispose();
            }
        }

        public static IEnumerable<object[]> ExplicitCreateFactories()
        {
            return new[]
            {
                #region Asymmetric algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, GostECDsa256AlgorithmName},
                new object[] { typeof(GostECDsa256), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, GostECDsa256AlgorithmFullName},
                new object[] { typeof(GostECDsa512), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, GostECDsa512AlgorithmName},
                new object[] { typeof(GostECDsa512), (Func<string, AsymmetricAlgorithm>)AsymmetricAlgorithm.Create, GostECDsa512AlgorithmFullName},

                #endregion

                #region Symmetric algorithm factories

                new object[] { typeof(Grasshopper), (Func<string, SymmetricAlgorithm>)SymmetricAlgorithm.Create, GrasshopperAlgorithmFullName},
                new object[] { typeof(Magma), (Func<string, SymmetricAlgorithm>)SymmetricAlgorithm.Create, MagmaAlgorithmFullName},

                #endregion

                #region Hash algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CMACGrasshopperAlgorithmFullName},
                new object[] { typeof(CMACMagma), (Func<string, HashAlgorithm>)HashAlgorithm.Create, CMACMagmaAlgorithmFullName},
                new object[] { typeof(Streebog256), (Func<string, HashAlgorithm>)HashAlgorithm.Create, Streebog256AlgorithmFullName},
                new object[] { typeof(Streebog512), (Func<string, HashAlgorithm>)HashAlgorithm.Create, Streebog512AlgorithmFullName},
                new object[] { typeof(HMACStreebog256), (Func<string, HashAlgorithm>)HashAlgorithm.Create, HMACStreebog256AlgorithmFullName},
                new object[] { typeof(HMACStreebog512), (Func<string, HashAlgorithm>)HashAlgorithm.Create, HMACStreebog512AlgorithmFullName},

                #endregion

                #region Keyed hash algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CMACGrasshopperAlgorithmFullName},
                new object[] { typeof(CMACMagma), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, CMACMagmaAlgorithmFullName},
                new object[] { typeof(HMACStreebog256), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, HMACStreebog256AlgorithmFullName},
                new object[] { typeof(HMACStreebog512), (Func<string, KeyedHashAlgorithm>)KeyedHashAlgorithm.Create, HMACStreebog512AlgorithmFullName},

                #endregion

                #region HMAC algorithm factories

                new object[] { typeof(HMACStreebog256), (Func<string, HMAC>)HMAC.Create, HMACStreebog256AlgorithmFullName},
                new object[] { typeof(HMACStreebog512), (Func<string, HMAC>)HMAC.Create, HMACStreebog512AlgorithmFullName},

                #endregion

                #region CMAC algorithm factories

                new object[] { typeof(CMACGrasshopper), (Func<string, CMAC>)CMAC.Create, CMACGrasshopperAlgorithmFullName},
                new object[] { typeof(CMACMagma), (Func<string, CMAC>)CMAC.Create, CMACMagmaAlgorithmFullName},

                #endregion

                #region GostECDsa algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa>)GostECDsa.Create, GostECDsa256AlgorithmName},
                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa>)GostECDsa.Create, GostECDsa256AlgorithmFullName},
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa>)GostECDsa.Create, GostECDsa512AlgorithmName},
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa>)GostECDsa.Create, GostECDsa512AlgorithmFullName},

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa256>)GostECDsa256.Create, GostECDsa256AlgorithmName},
                new object[] { typeof(GostECDsa256), (Func<string, GostECDsa256>)GostECDsa256.Create, GostECDsa256AlgorithmFullName},

                #endregion

                #region GostECDsa256 algorithm factories

                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa512>)GostECDsa512.Create, GostECDsa512AlgorithmName},
                new object[] { typeof(GostECDsa512), (Func<string, GostECDsa512>)GostECDsa512.Create, GostECDsa512AlgorithmFullName},

                #endregion

                #region Grasshopper algorithm factories

                new object[] { typeof(Grasshopper), (Func<string, Grasshopper>)Grasshopper.Create, GrasshopperAlgorithmFullName},

                #endregion

                #region Magma algorithm factories

                new object[] { typeof(Magma), (Func<string, Magma>)Magma.Create, MagmaAlgorithmFullName},

                #endregion

                #region Streebog256 algorithm factories

                new object[] { typeof(Streebog256), (Func<string, Streebog256>)Streebog256.Create, Streebog256AlgorithmFullName},

                #endregion

                #region Streebog512 algorithm factories

                new object[] { typeof(Streebog512), (Func<string, Streebog512>)Streebog512.Create, Streebog512AlgorithmFullName},

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
