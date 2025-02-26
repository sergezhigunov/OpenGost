namespace OpenGost.Security.Cryptography.Tests;

public class GrasshopperFacts
{
    [Fact]
    public void Create_Parameterless_CreatesDefaultImplementation()
    {
        using var algorithm = Grasshopper.Create();

        Assert.IsType<GrasshopperManaged>(algorithm, true);
    }
}
