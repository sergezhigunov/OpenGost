namespace OpenGost.Security.Cryptography.Tests;

public class Streebog256Facts
{
    [Fact]
    public void Create_Parameterless_CreatesDefaultImplementation()
    {
        using var algorithm = Streebog256.Create();

        Assert.IsType<Streebog256Managed>(algorithm, true);
    }
}
