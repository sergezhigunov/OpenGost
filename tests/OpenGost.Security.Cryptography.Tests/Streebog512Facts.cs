namespace OpenGost.Security.Cryptography.Tests;

public class Streebog512Facts
{
    [Fact]
    public void Create_Parameterless_CreatesDefaultImplementation()
    {
        using var algorithm = Streebog512.Create();

        Assert.IsType<Streebog512Managed>(algorithm, true);
    }
}
