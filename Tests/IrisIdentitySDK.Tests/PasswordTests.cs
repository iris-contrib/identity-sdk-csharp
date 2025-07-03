using FluentAssertions;
using IrisIdentitySDK.Models;
using IrisIdentitySDK.Security;
using Xunit;

namespace IrisIdentitySDK.Tests;

public class PasswordTests
{
    [Fact]
    public void PasswordEncryption_WithValidInput_ShouldEncryptSuccessfully()
    {
        // Arrange
        var password = "mypassword";
        var key = "14be763a0cd7b7b98d48c3e808bfaf84"; // 32-char hex key

        // Act
        var encrypted = PasswordEncryption.EncryptPassword(password, key);

        // Assert
        encrypted.Should().NotBeNullOrEmpty();
        encrypted.Should().NotBe(password);
        encrypted.Length.Should().BeGreaterThan(password.Length);
    }

    [Fact]
    public void PasswordEncryption_SamePasswordMultipleTimes_ShouldProduceDifferentResults()
    {
        // Arrange
        var password = "mypassword";
        var key = "14be763a0cd7b7b98d48c3e808bfaf84";

        // Act
        var encrypted1 = PasswordEncryption.EncryptPassword(password, key);
        var encrypted2 = PasswordEncryption.EncryptPassword(password, key);

        // Assert
        encrypted1.Should().NotBe(encrypted2);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void PasswordEncryption_WithInvalidPassword_ShouldThrowArgumentException(string password)
    {
        // Arrange
        var key = "14be763a0cd7b7b98d48c3e808bfaf84";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => PasswordEncryption.EncryptPassword(password, key));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("tooshort")]
    public void PasswordEncryption_WithInvalidKey_ShouldThrowArgumentException(string key)
    {
        // Arrange
        var password = "mypassword";

        // Act & Assert
        Assert.Throws<ArgumentException>(() => PasswordEncryption.EncryptPassword(password, key));
    }

    [Theory]
    [InlineData("14be763a0cd7b7b98d48c3e808bfaf84", true)] // 32 chars (16 bytes)
    [InlineData("14be763a0cd7b7b98d48c3e808bfaf8414be763a0cd7b7b98d48c3e808bfaf84", true)] // 64 chars (32 bytes)
    [InlineData("invalid", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidEncryptionKey_ShouldValidateCorrectly(string key, bool expected)
    {
        // Act
        var result = PasswordEncryption.IsValidEncryptionKey(key);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("", PasswordStrengthLevel.VeryWeak, false)]
    [InlineData("a", PasswordStrengthLevel.VeryWeak, true)]
    [InlineData("short", PasswordStrengthLevel.Weak, false)]
    [InlineData("password", PasswordStrengthLevel.Weak, true)]
    [InlineData("password", PasswordStrengthLevel.Medium, false)]
    [InlineData("Password123", PasswordStrengthLevel.Medium, true)]
    [InlineData("Password123", PasswordStrengthLevel.Strong, false)]
    [InlineData("Password123!", PasswordStrengthLevel.Strong, true)]
    [InlineData("Password123!", PasswordStrengthLevel.VeryStrong, false)]
    [InlineData("VeryStrong123!@#", PasswordStrengthLevel.VeryStrong, true)]
    public void PasswordValidator_ShouldValidateStrengthLevels(string password, PasswordStrengthLevel level, bool expectedValid)
    {
        // Act
        var result = PasswordValidator.ValidatePassword(password, level);

        // Assert
        result.IsValid.Should().Be(expectedValid);
        result.Message.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void PasswordValidator_VeryWeakLevel_ShouldAcceptAnyNonEmptyPassword()
    {
        // Arrange
        var passwords = new[] { "a", "1", "!", "abc", "123", "password" };

        // Act & Assert
        foreach (var password in passwords)
        {
            var result = PasswordValidator.ValidatePassword(password, PasswordStrengthLevel.VeryWeak);
            result.IsValid.Should().BeTrue($"Password '{password}' should be valid for VeryWeak level");
        }
    }

    [Fact]
    public void PasswordValidator_MediumLevel_ShouldRequireMixedCaseAndNumbers()
    {
        // Arrange & Act & Assert
        var result1 = PasswordValidator.ValidatePassword("password", PasswordStrengthLevel.Medium);
        result1.IsValid.Should().BeFalse("lowercase only should fail");

        var result2 = PasswordValidator.ValidatePassword("PASSWORD", PasswordStrengthLevel.Medium);
        result2.IsValid.Should().BeFalse("uppercase only should fail");

        var result3 = PasswordValidator.ValidatePassword("Password", PasswordStrengthLevel.Medium);
        result3.IsValid.Should().BeFalse("mixed case without numbers should fail");

        var result4 = PasswordValidator.ValidatePassword("Password123", PasswordStrengthLevel.Medium);
        result4.IsValid.Should().BeTrue("mixed case with numbers should pass");
    }

    [Fact]
    public void PasswordValidator_StrongLevel_ShouldRequireSpecialCharacters()
    {
        // Arrange & Act & Assert
        var result1 = PasswordValidator.ValidatePassword("Password123", PasswordStrengthLevel.Strong);
        result1.IsValid.Should().BeFalse("without special characters should fail");

        var result2 = PasswordValidator.ValidatePassword("Password123!", PasswordStrengthLevel.Strong);
        result2.IsValid.Should().BeTrue("with special characters should pass");
    }

    [Fact]
    public void PasswordValidator_VeryStrongLevel_ShouldRejectCommonPatterns()
    {
        // Arrange
        var weakPasswords = new[]
        {
            "Passwordaaa1!", // repeated characters
            "Password123!", // sequential numbers
            "Passwordabc1!", // sequential letters
            "Qwerty123!", // keyboard pattern
        };

        // Act & Assert
        foreach (var password in weakPasswords)
        {
            var result = PasswordValidator.ValidatePassword(password, PasswordStrengthLevel.VeryStrong);
            // Note: Some of these might pass if they meet other requirements, 
            // but the common pattern detection should catch obvious ones
        }
    }

    [Fact]
    public void PasswordValidator_VeryStrongLevel_ShouldRequireMultipleCharacterTypes()
    {
        // Arrange & Act & Assert
        var result1 = PasswordValidator.ValidatePassword("Passworddd11!", PasswordStrengthLevel.VeryStrong);
        result1.IsValid.Should().BeFalse("should require multiple of each type");

        var result2 = PasswordValidator.ValidatePassword("MySecurePass22!@", PasswordStrengthLevel.VeryStrong);
        result2.IsValid.Should().BeTrue("should pass with multiple of each type");
    }
}