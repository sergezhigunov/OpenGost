using System.Reflection;
using BenchmarkDotNet.Running;

namespace OpenGost.Security.Cryptography.Benchmarks;

internal static class Program
{
    private static void Main(string[] args)
        => BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args);
}
