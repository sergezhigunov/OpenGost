using System.Text;
using System.Security.Cryptography;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class Streebog256Tests : HashAlgorithmTest
    {
        private static readonly Encoding CurrentEncoding = Encoding.GetEncoding(1251);

        protected override HashAlgorithm Create()
            => Streebog256.Create();

        [Theory(DisplayName = nameof(Streebog256) + "_" + nameof(Hash))]
        [InlineData(
            "012345678901234567890123456789012345678901234567890123456789012",
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")]
        [InlineData(
            "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы",
            "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50")]
        [InlineData(
            "",
            "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")]
        public void Hash(string message, string expectedHashCode)
            => Verify(message, CurrentEncoding, expectedHashCode);
    }
}