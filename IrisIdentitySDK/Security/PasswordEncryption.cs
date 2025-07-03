using System.Security.Cryptography;
using System.Text;

namespace IrisIdentitySDK.Security;

/// <summary>
/// Provides AES-GCM encryption for password transmission
/// </summary>
public static class PasswordEncryption
{
    /// <summary>
    /// Encrypts a plain password using AES-GCM with the provided shared key
    /// </summary>
    /// <param name="plainPassword">The plain text password</param>
    /// <param name="sharedKeyHex">The shared encryption key as hex string</param>
    /// <returns>Encrypted password as hex string</returns>
    /// <exception cref="ArgumentException">Thrown when key format is invalid</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    public static string EncryptPassword(string plainPassword, string sharedKeyHex)
    {
        if (string.IsNullOrEmpty(plainPassword))
            throw new ArgumentException("Password cannot be null or empty", nameof(plainPassword));
        
        if (string.IsNullOrEmpty(sharedKeyHex))
            throw new ArgumentException("Shared key cannot be null or empty", nameof(sharedKeyHex));

        try
        {
            // Convert hex string to bytes
            var sharedKey = Convert.FromHexString(sharedKeyHex);
            
            // Validate key length (16, 24, or 32 bytes for AES)
            if (sharedKey.Length != 16 && sharedKey.Length != 24 && sharedKey.Length != 32)
            {
                throw new ArgumentException("Invalid key length. Key must be 16, 24, or 32 bytes.", nameof(sharedKeyHex));
            }

            var plainBytes = Encoding.UTF8.GetBytes(plainPassword);
            
            using var aes = new AesGcm(sharedKey);
            
            // Generate random nonce
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);
            
            // Encrypt the password
            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            
            aes.Encrypt(nonce, plainBytes, ciphertext, tag);
            
            // Combine nonce + ciphertext + tag
            var result = new byte[nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);
            
            return Convert.ToHexString(result);
        }
        catch (Exception ex) when (!(ex is ArgumentException))
        {
            throw new CryptographicException("Failed to encrypt password", ex);
        }
    }

    /// <summary>
    /// Validates the format of a hex-encoded encryption key
    /// </summary>
    /// <param name="keyHex">The key to validate</param>
    /// <returns>True if the key format is valid</returns>
    public static bool IsValidEncryptionKey(string keyHex)
    {
        if (string.IsNullOrEmpty(keyHex))
            return false;

        try
        {
            var keyBytes = Convert.FromHexString(keyHex);
            return keyBytes.Length == 16 || keyBytes.Length == 24 || keyBytes.Length == 32;
        }
        catch
        {
            return false;
        }
    }
}