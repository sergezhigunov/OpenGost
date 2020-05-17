using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class Streebog512ManagedTests : HashAlgorithmTest<Streebog512Managed>
    {
        [Theory]
        [InlineData(
            // "012345678901234567890123456789012345678901234567890123456789012"
            "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132",
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48")]
        [InlineData(
            // "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы"
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb",
            "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28")]
        [InlineData(
            "",
            "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")]
        public void Hash(string message, string expected)
            => Verify(message, expected);
    }
}
