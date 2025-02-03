namespace OpenGost.Security.Cryptography;

internal static class Oids
{
    // Gost ECDSA
    internal const string GostECDsa256 = "1.2.643.7.1.1.1.1";
    internal const string GostECDsa512 = "1.2.643.7.1.1.1.2";

    // Hash Algorithms
    internal const string Streebog256 = "1.2.643.7.1.1.2.2";
    internal const string Streebog512 = "1.2.643.7.1.1.2.3";

    // Elliptic Curve identifiers
    internal const string ECCurveCryptoProTestParamSet = "1.2.643.2.2.35.0";
    internal const string ECCurveCryptoProParamSetA = "1.2.643.2.2.35.1";
    internal const string ECCurveCryptoProParamSetB = "1.2.643.2.2.35.2";
    internal const string ECCurveCryptoProParamSetC = "1.2.643.2.2.35.3";
    internal const string ECCurveCryptoProParamSetXchA = "1.2.643.2.2.36.0";
    internal const string ECCurveCryptoProParamSetXchB = "1.2.643.2.2.36.1";
    internal const string ECCurve256TestParamSet = "1.2.643.7.1.2.1.1.0";
    internal const string ECCurve256ParamSetA = "1.2.643.7.1.2.1.1.1";
    internal const string ECCurve256ParamSetB = "1.2.643.7.1.2.1.1.2";
    internal const string ECCurve256ParamSetC = "1.2.643.7.1.2.1.1.3";
    internal const string ECCurve256ParamSetD = "1.2.643.7.1.2.1.1.4";
    internal const string ECCurve512TestParamSet = "1.2.643.7.1.2.1.2.0";
    internal const string ECCurve512ParamSetA = "1.2.643.7.1.2.1.2.1";
    internal const string ECCurve512ParamSetB = "1.2.643.7.1.2.1.2.2";
    internal const string ECCurve512ParamSetC = "1.2.643.7.1.2.1.2.3";

    // Cert Extensions
    internal const string KeyUsage = "2.5.29.15";
}
