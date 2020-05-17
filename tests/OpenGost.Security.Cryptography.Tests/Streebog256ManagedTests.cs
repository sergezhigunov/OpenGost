using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class Streebog256ManagedTests : HashAlgorithmTest<Streebog256Managed>
    {
        [Theory]
        [InlineData(
            // "012345678901234567890123456789012345678901234567890123456789012"
            "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132",
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")]
        [InlineData(
            // "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы"
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb",
            "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50")]
        [InlineData(
            "",
            "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")]
        public void Hash(string message, string expected)
            => Verify(message, expected);
    }
}
