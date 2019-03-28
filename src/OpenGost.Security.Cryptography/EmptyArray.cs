#if NET45
namespace OpenGost.Security.Cryptography
{
    internal static class EmptyArray<T>
    {
        public static T[] Value { get; } = new T[0];
    }
}
#endif
