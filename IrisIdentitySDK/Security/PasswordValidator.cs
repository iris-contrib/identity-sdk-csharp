using System.Text.RegularExpressions;
using IrisIdentitySDK.Models;

namespace IrisIdentitySDK.Security;

/// <summary>
/// Validates password strength according to configured levels
/// </summary>
public static class PasswordValidator
{
    /// <summary>
    /// Validates password strength according to the specified level
    /// </summary>
    /// <param name="password">Password to validate</param>
    /// <param name="level">Required strength level</param>
    /// <returns>Validation result</returns>
    public static PasswordValidationResult ValidatePassword(string password, PasswordStrengthLevel level)
    {
        if (string.IsNullOrEmpty(password))
        {
            return new PasswordValidationResult(false, "Password cannot be empty");
        }

        return level switch
        {
            PasswordStrengthLevel.VeryWeak => ValidateVeryWeak(password),
            PasswordStrengthLevel.Weak => ValidateWeak(password),
            PasswordStrengthLevel.Medium => ValidateMedium(password),
            PasswordStrengthLevel.Strong => ValidateStrong(password),
            PasswordStrengthLevel.VeryStrong => ValidateVeryStrong(password),
            _ => new PasswordValidationResult(false, "Invalid password strength level")
        };
    }

    private static PasswordValidationResult ValidateVeryWeak(string password)
    {
        if (password.Length < 1)
        {
            return new PasswordValidationResult(false, "Password must be at least 1 character long");
        }
        return new PasswordValidationResult(true, "Password meets very weak requirements");
    }

    private static PasswordValidationResult ValidateWeak(string password)
    {
        if (password.Length < 6)
        {
            return new PasswordValidationResult(false, "Password must be at least 6 characters long");
        }
        return new PasswordValidationResult(true, "Password meets weak requirements");
    }

    private static PasswordValidationResult ValidateMedium(string password)
    {
        if (password.Length < 8)
        {
            return new PasswordValidationResult(false, "Password must be at least 8 characters long");
        }

        var hasLower = Regex.IsMatch(password, @"[a-z]");
        var hasUpper = Regex.IsMatch(password, @"[A-Z]");
        var hasDigit = Regex.IsMatch(password, @"\d");

        if (!hasLower)
        {
            return new PasswordValidationResult(false, "Password must contain at least one lowercase letter");
        }

        if (!hasUpper)
        {
            return new PasswordValidationResult(false, "Password must contain at least one uppercase letter");
        }

        if (!hasDigit)
        {
            return new PasswordValidationResult(false, "Password must contain at least one digit");
        }

        return new PasswordValidationResult(true, "Password meets medium requirements");
    }

    private static PasswordValidationResult ValidateStrong(string password)
    {
        var mediumResult = ValidateMedium(password);
        if (!mediumResult.IsValid)
        {
            return mediumResult;
        }

        if (password.Length < 10)
        {
            return new PasswordValidationResult(false, "Password must be at least 10 characters long");
        }

        var hasSpecial = Regex.IsMatch(password, @"[!@#$%^&*(),.?\"":{}|<>]");
        if (!hasSpecial)
        {
            return new PasswordValidationResult(false, "Password must contain at least one special character");
        }

        return new PasswordValidationResult(true, "Password meets strong requirements");
    }

    private static PasswordValidationResult ValidateVeryStrong(string password)
    {
        var strongResult = ValidateStrong(password);
        if (!strongResult.IsValid)
        {
            return strongResult;
        }

        if (password.Length < 12)
        {
            return new PasswordValidationResult(false, "Password must be at least 12 characters long");
        }

        // Check for multiple character types
        var lowerCount = password.Count(char.IsLower);
        var upperCount = password.Count(char.IsUpper);
        var digitCount = password.Count(char.IsDigit);
        var specialCount = password.Count(c => "!@#$%^&*(),.?\":{}|<>".Contains(c));

        if (lowerCount < 2)
        {
            return new PasswordValidationResult(false, "Password must contain at least 2 lowercase letters");
        }

        if (upperCount < 2)
        {
            return new PasswordValidationResult(false, "Password must contain at least 2 uppercase letters");
        }

        if (digitCount < 2)
        {
            return new PasswordValidationResult(false, "Password must contain at least 2 digits");
        }

        if (specialCount < 2)
        {
            return new PasswordValidationResult(false, "Password must contain at least 2 special characters");
        }

        // Check for common patterns
        if (HasCommonPatterns(password))
        {
            return new PasswordValidationResult(false, "Password contains common patterns and is not secure");
        }

        return new PasswordValidationResult(true, "Password meets very strong requirements");
    }

    private static bool HasCommonPatterns(string password)
    {
        var commonPatterns = new[]
        {
            @"(.)\1{2,}", // Repeated characters (aaa, 111, etc.)
            @"(012|123|234|345|456|567|678|789|890)", // Sequential numbers
            @"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", // Sequential letters
            @"(qwerty|asdfgh|zxcvbn)", // Keyboard patterns
        };

        return commonPatterns.Any(pattern => Regex.IsMatch(password.ToLower(), pattern));
    }
}

/// <summary>
/// Result of password validation
/// </summary>
public class PasswordValidationResult
{
    public bool IsValid { get; }
    public string Message { get; }

    public PasswordValidationResult(bool isValid, string message)
    {
        IsValid = isValid;
        Message = message;
    }
}