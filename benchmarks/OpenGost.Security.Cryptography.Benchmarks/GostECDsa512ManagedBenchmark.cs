namespace OpenGost.Security.Cryptography.Benchmarks;

public class GostECDsa512ManagedBenchmark
    : ECDsaBenchmark<GostECDsaManaged>
{
    public GostECDsa512ManagedBenchmark()
        : base(512)
    {
    }
}
