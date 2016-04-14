namespace Gost.Security.Cryptography
{
    internal static class EmptyArray<T>
    {
        public static T[] Value { get; } = new T[0];
    }
}
