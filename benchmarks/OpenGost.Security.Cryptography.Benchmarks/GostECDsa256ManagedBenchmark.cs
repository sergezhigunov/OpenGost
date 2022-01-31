namespace OpenGost.Security.Cryptography.Benchmarks;

public class GostECDsa256ManagedBenchmark
    : ECDsaBenchmark<GostECDsaManaged>
{
    public GostECDsa256ManagedBenchmark()
        : base(256)
    {
    }
}
