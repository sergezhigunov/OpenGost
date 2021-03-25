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
        public void CreateExplicit_ReturnsValidInstance(
            Type expectedType,
            Func<string, object?> factory,
            string objectName)
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

        public static IEnumerable<object?[]> ExplicitCreateFactories()
        {
            static object?[] TestCase(Type type, Func<string, object?> factory, bool fullName)
                => new object?[] { type, factory, fullName ? type.FullName : type.Name };

            return new[]
            {
                #region Asymmetric algorithm factories

                TestCase(typeof(GostECDsa256), AsymmetricAlgorithm.Create, false),
                TestCase(typeof(GostECDsa256), AsymmetricAlgorithm.Create, true),
                TestCase(typeof(GostECDsa512), AsymmetricAlgorithm.Create, false),
                TestCase(typeof(GostECDsa512), AsymmetricAlgorithm.Create, true),

                #endregion

                #region Symmetric algorithm factories

                TestCase(typeof(Grasshopper), SymmetricAlgorithm.Create, false),
                TestCase(typeof(Grasshopper), SymmetricAlgorithm.Create, true),
                TestCase(typeof(Magma), SymmetricAlgorithm.Create, false),
                TestCase(typeof(Magma), SymmetricAlgorithm.Create, true),

                #endregion

                #region Hash algorithm factories

                TestCase(typeof(CMACGrasshopper), HashAlgorithm.Create, false),
                TestCase(typeof(CMACGrasshopper), HashAlgorithm.Create, true),
                TestCase(typeof(CMACMagma), HashAlgorithm.Create, false),
                TestCase(typeof(CMACMagma), HashAlgorithm.Create, true),
                TestCase(typeof(Streebog256), HashAlgorithm.Create, false),
                TestCase(typeof(Streebog256), HashAlgorithm.Create, true),
                TestCase(typeof(Streebog512), HashAlgorithm.Create, false),
                TestCase(typeof(Streebog512), HashAlgorithm.Create, true),
                TestCase(typeof(HMACStreebog256), HashAlgorithm.Create, false),
                TestCase(typeof(HMACStreebog256), HashAlgorithm.Create, true),
                TestCase(typeof(HMACStreebog512), HashAlgorithm.Create, false),
                TestCase(typeof(HMACStreebog512), HashAlgorithm.Create, true),

                #endregion

                #region Keyed hash algorithm factories

                TestCase(typeof(CMACGrasshopper), KeyedHashAlgorithm.Create, false),
                TestCase(typeof(CMACGrasshopper), KeyedHashAlgorithm.Create, true),
                TestCase(typeof(CMACMagma), KeyedHashAlgorithm.Create, false),
                TestCase(typeof(CMACMagma), KeyedHashAlgorithm.Create, true),
                TestCase(typeof(HMACStreebog256), KeyedHashAlgorithm.Create, false),
                TestCase(typeof(HMACStreebog256), KeyedHashAlgorithm.Create, true),
                TestCase(typeof(HMACStreebog512), KeyedHashAlgorithm.Create, false),
                TestCase(typeof(HMACStreebog512), KeyedHashAlgorithm.Create, true),

                #endregion

                #region HMAC algorithm factories

                TestCase(typeof(HMACStreebog256), HMAC.Create, false),
                TestCase(typeof(HMACStreebog256), HMAC.Create, true),
                TestCase(typeof(HMACStreebog512), HMAC.Create, false),
                TestCase(typeof(HMACStreebog512), HMAC.Create, true),

                #endregion

                #region CMAC algorithm factories

                TestCase(typeof(CMACGrasshopper), CMAC.Create, false),
                TestCase(typeof(CMACGrasshopper), CMAC.Create, true),
                TestCase(typeof(CMACMagma), CMAC.Create, false),
                TestCase(typeof(CMACMagma), CMAC.Create, true),

                #endregion

                #region ECDsa algorithm factories

                TestCase(typeof(GostECDsa256), ECDsa.Create, false),
                TestCase(typeof(GostECDsa256), ECDsa.Create, true),
                TestCase(typeof(GostECDsa512), ECDsa.Create, false),
                TestCase(typeof(GostECDsa512), ECDsa.Create, true),

                #endregion

                #region GostECDsa256 algorithm factories

                TestCase(typeof(GostECDsa256), GostECDsa256.Create, false),
                TestCase(typeof(GostECDsa256), GostECDsa256.Create, true),

                #endregion

                #region GostECDsa256 algorithm factories

                TestCase(typeof(GostECDsa512), GostECDsa512.Create, false),
                TestCase(typeof(GostECDsa512), GostECDsa512.Create, true),

                #endregion

                #region Grasshopper algorithm factories

                TestCase(typeof(Grasshopper), Grasshopper.Create, false),
                TestCase(typeof(Grasshopper), Grasshopper.Create, true),

                #endregion

                #region Magma algorithm factories

                TestCase(typeof(Magma), Magma.Create, false),
                TestCase(typeof(Magma), Magma.Create, true),

                #endregion

                #region Streebog256 algorithm factories

                TestCase(typeof(Streebog256), Streebog256.Create, false),
                TestCase(typeof(Streebog256), Streebog256.Create, true),

                #endregion

                #region Streebog512 algorithm factories

                TestCase(typeof(Streebog512), Streebog512.Create, false),
                TestCase(typeof(Streebog512), Streebog512.Create, true),

                #endregion
            };
        }

        public static IEnumerable<object[]> ImplicitCreateFactories()
        {
            static Func<T> Func<T>(Func<T> func) => func;

            return new[]
            {
                new object[] { typeof(CMACGrasshopper), Func(CMAC.Create), },
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
