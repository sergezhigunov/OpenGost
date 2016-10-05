using System.Text;
using Xunit;

namespace OpenGost.Security.Cryptography
{
    public class Streebog512ManagedTests : HashAlgorithmTest<Streebog512Managed>
    {
        private static readonly Encoding CurrentEncoding = Encoding.GetEncoding(1251);

        [Theory(DisplayName = nameof(Streebog512) + "_" + nameof(Hash))]
        [InlineData(
            "012345678901234567890123456789012345678901234567890123456789012",
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48")]
        [InlineData(
            "Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы",
            "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28")]
        [InlineData(
            "",
            "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")]
        public void Hash(string message, string expectedHashCode)
            => Verify(message, CurrentEncoding, expectedHashCode);
    }
}
