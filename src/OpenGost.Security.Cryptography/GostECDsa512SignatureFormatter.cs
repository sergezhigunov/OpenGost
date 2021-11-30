﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using OpenGost.Security.Cryptography.Properties;

namespace OpenGost.Security.Cryptography;

/// <summary>
/// Creates a <see cref="GostECDsa512"/> signature.
/// </summary>
[ComVisible(true)]
public class GostECDsa512SignatureFormatter : AsymmetricSignatureFormatter
{
    private readonly string? _oid;
    private GostECDsa512? _key;

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa512SignatureFormatter"/> class.
    /// </summary>
    public GostECDsa512SignatureFormatter()
    {
        _oid = CryptoConfig.MapNameToOID(CryptoConstants.Streebog512AlgorithmFullName);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GostECDsa512SignatureFormatter"/> class with the specified key.
    /// </summary>
    /// <param name="key">
    /// The instance of <see cref="GostECDsa512"/> that holds the key.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="key"/> is <see langword="null"/>.
    /// </exception>
    public GostECDsa512SignatureFormatter(AsymmetricAlgorithm key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        _key = (GostECDsa512)key;
    }

    /// <summary>
    /// Creates the <see cref="GostECDsa512"/> signature for the specified data.
    /// </summary>
    /// <param name="rgbHash">
    /// The data to be signed.
    /// </param>
    /// <returns>
    /// The digital signature for the specified data.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="rgbHash"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="CryptographicUnexpectedOperationException">
    /// The OID is <see langword="null"/>.
    /// </exception>
    /// <exception cref="CryptographicUnexpectedOperationException">
    /// The <see cref="GostECDsa512"/> key is <see langword="null"/>.
    /// </exception>
    public override byte[] CreateSignature(byte[] rgbHash)
    {
        if (rgbHash == null)
            throw new ArgumentNullException(nameof(rgbHash));
        if (_oid == null)
            throw new CryptographicUnexpectedOperationException(CryptographyStrings.CryptographicMissingOid);
        if (_key == null)
            throw new CryptographicUnexpectedOperationException(CryptographyStrings.CryptographicMissingKey);

        return _key.SignHash(rgbHash);
    }

    /// <summary>
    /// Specifies the hash algorithm for the <see cref="GostECDsa512"/> signature formatter.
    /// </summary>
    /// <param name="strName">
    /// The name of the hash algorithm to use for the signature formatter.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="strName"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="CryptographicUnexpectedOperationException">
    /// The <paramref name="strName"/> parameter does not map to the <see cref="Streebog512"/>
    /// hash algorithm.
    /// </exception>
    public override void SetHashAlgorithm(string strName)
    {
        if (strName == null)
            throw new ArgumentNullException(nameof(strName));

        if (CryptoConfig.MapNameToOID(strName) != _oid)
            throw new CryptographicUnexpectedOperationException(CryptographyStrings.CryptographicInvalidOperation);
    }

    /// <summary>
    /// Specifies the key to be used for the <see cref="GostECDsa512"/> signature formatter.
    /// </summary>
    /// <param name="key">
    /// The instance of <see cref="GostECDsa512"/> that holds the key.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="key"/> is <see langword="null"/>.
    /// </exception>
    public override void SetKey(AsymmetricAlgorithm key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        _key = (GostECDsa512)key;
    }
}
