namespace OpenGost.Security.Cryptography.Tests;

public class MagmaFacts
{
    [Fact]
    public void Create_Parameterless_CreatesDefaultImplementation()
    {
        using var algorithm = Magma.Create();

        Assert.IsType<MagmaManaged>(algorithm, true);
    }
}
