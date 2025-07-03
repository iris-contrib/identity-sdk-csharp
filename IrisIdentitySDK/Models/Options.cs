using System.ComponentModel.DataAnnotations;

namespace IrisIdentitySDK.Models;

/// <summary>
/// Configuration options for the Iris Identity SDK
/// </summary>
public class IdentityOptions
{
    /// <summary>
    /// The base URL of the identity server
    /// </summary>
    [Required]
    public string BaseURL { get; set; } = string.Empty;

    /// <summary>
    /// The client token to authenticate with the identity server
    /// </summary>
    [Required]
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// The encryption key to encrypt the user password (32-character hex string)
    /// </summary>
    [Required]
    public string EncryptionKey { get; set; } = string.Empty;

    /// <summary>
    /// Password strength validation level
    /// </summary>
    public PasswordStrengthLevel PasswordStrengthLevel { get; set; } = PasswordStrengthLevel.VeryWeak;
}

/// <summary>
/// Password strength levels for validation
/// </summary>
public enum PasswordStrengthLevel
{
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong
}