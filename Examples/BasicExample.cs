using IrisIdentitySDK;
using IrisIdentitySDK.Models;
using System.Text.Json.Serialization;

namespace IrisIdentitySDK.Examples;

/// <summary>
/// Custom user model for this example
/// </summary>
public class ExampleUser : User
{
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [JsonPropertyName("firstname")]
    public string FirstName { get; set; } = string.Empty;

    [JsonPropertyName("lastname")]
    public string LastName { get; set; } = string.Empty;

    [JsonPropertyName("phone")]
    public string Phone { get; set; } = string.Empty;

    [JsonPropertyName("company")]
    public string Company { get; set; } = string.Empty;
}

/// <summary>
/// Basic example demonstrating core SDK functionality
/// </summary>
public class BasicExample
{
    private readonly IdentitySDK<ExampleUser> _sdk;

    public BasicExample()
    {
        var options = new IdentityOptions
        {
            BaseURL = "https://identity.example.com",
            Token = Environment.GetEnvironmentVariable("IDENTITY_CLIENT_TOKEN") ?? throw new InvalidOperationException("IDENTITY_CLIENT_TOKEN environment variable is required"),
            EncryptionKey = Environment.GetEnvironmentVariable("IDENTITY_ENCRYPTION_KEY") ?? throw new InvalidOperationException("IDENTITY_ENCRYPTION_KEY environment variable is required"),
            PasswordStrengthLevel = PasswordStrengthLevel.Medium
        };

        _sdk = new IdentitySDK<ExampleUser>(options);
    }

    /// <summary>
    /// Demonstrates basic user authentication flow
    /// </summary>
    public async Task AuthenticationExampleAsync()
    {
        try
        {
            // Initialize the SDK
            await _sdk.InitializeAsync();
            Console.WriteLine("SDK initialized successfully");

            // Sign in a user
            var token = await _sdk.UserSigninAsync("user@example.com", "password123");
            Console.WriteLine($"User signed in successfully");
            Console.WriteLine($"Access Token: {token.AccessToken[..20]}...");
            Console.WriteLine($"Token expires: {token.Expiry}");

            // Verify the token
            var user = await _sdk.VerifyTokenAsync(token.AccessToken);
            Console.WriteLine($"Token verified for user: {user.Username}");

            // Introspect token via server
            var serverUser = await _sdk.TokenIntrospectAsync(token.AccessToken);
            Console.WriteLine($"Server introspection successful: {serverUser.Email}");
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"HTTP error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Demonstrates user registration and management
    /// </summary>
    public async Task UserManagementExampleAsync()
    {
        try
        {
            await _sdk.InitializeAsync();

            // Create a new user
            var newUser = new ExampleUser
            {
                Username = "johndoe",
                Email = "john.doe@example.com",
                FirstName = "John",
                LastName = "Doe",
                Phone = "+1-555-123-4567",
                Company = "Example Corp"
            };

            Console.WriteLine("Creating new user...");
            var token = await _sdk.AdminUserSignupAsync(newUser, "SecurePassword123!");
            Console.WriteLine($"User created successfully: {newUser.Username}");

            // Get user schema
            var schema = await _sdk.AdminGetUserSchemaAsync();
            Console.WriteLine($"User schema has {schema.Length} attributes:");
            foreach (var attr in schema.Take(3))
            {
                Console.WriteLine($"  - {attr.Name} ({attr.Type})");
            }

            // List users with filtering
            var pageOptions = new PageOptions { Page = 1, Size = 5 };
            var filter = new UserFilterOptions
            {
                Sort = "created_at",
                SortDescending = true,
                Terms = new[]
                {
                    new FilterTerm
                    {
                        Field = "email",
                        Operator = "ILIKE",
                        Value = "%example.com%"
                    }
                }
            };

            var users = await _sdk.AdminListUsersAsync(pageOptions, filter);
            Console.WriteLine($"Found {users.Total} users matching filter");
            Console.WriteLine($"Showing {users.Items.Length} users on page {users.Page}");

            foreach (var user in users.Items.Take(3))
            {
                Console.WriteLine($"  - {user.Username} ({user.Email})");
            }
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Validation error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Demonstrates admin operations
    /// </summary>
    public async Task AdminOperationsExampleAsync()
    {
        try
        {
            await _sdk.InitializeAsync();

            var userIdentifier = "johndoe";

            // Reset user password
            Console.WriteLine("Resetting user password...");
            var resetRequest = new AdminResetUserPasswordRequest
            {
                Identifier = userIdentifier,
                Password = "NewSecurePassword456!"
            };

            bool passwordReset = await _sdk.AdminResetUserPasswordAsync(resetRequest);
            Console.WriteLine($"Password reset: {passwordReset}");

            // Admin signin (no password required)
            Console.WriteLine("Performing admin signin...");
            var adminSigninRequest = new AdminUserSigninRequest
            {
                Identifier = userIdentifier
            };

            var adminToken = await _sdk.AdminUserSigninAsync(adminSigninRequest);
            Console.WriteLine($"Admin signin successful");

            // Soft delete user
            Console.WriteLine("Soft deleting user...");
            var deleteRequest = new AdminDeleteUserRequest
            {
                Identifier = userIdentifier,
                Soft = true
            };

            bool deleted = await _sdk.AdminDeleteUserAsync(deleteRequest);
            Console.WriteLine($"User soft deleted: {deleted}");

            // Restore user
            Console.WriteLine("Restoring user...");
            var restoreRequest = new AdminRestoreUserRequest
            {
                Identifier = userIdentifier
            };

            bool restored = await _sdk.AdminRestoreUserAsync(restoreRequest);
            Console.WriteLine($"User restored: {restored}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Demonstrates bulk operations
    /// </summary>
    public async Task BulkOperationsExampleAsync()
    {
        try
        {
            await _sdk.InitializeAsync();

            // Update multiple users
            var usersToUpdate = new[]
            {
                new ExampleUser { Id = "user-1", Company = "New Company A" },
                new ExampleUser { Id = "user-2", Company = "New Company B" },
                new ExampleUser { Id = "user-3", Company = "New Company C" }
            };

            Console.WriteLine("Updating multiple users...");
            var result = await _sdk.AdminUpdateUsersAsync(usersToUpdate, new[] { "company" });
            Console.WriteLine($"Updated {result.Count} users");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Runs all examples
    /// </summary>
    public async Task RunAllExamplesAsync()
    {
        Console.WriteLine("=== Iris Identity SDK C# Examples ===\n");

        Console.WriteLine("1. Authentication Example");
        Console.WriteLine("=" * 40);
        await AuthenticationExampleAsync();
        Console.WriteLine();

        Console.WriteLine("2. User Management Example");
        Console.WriteLine("=" * 40);
        await UserManagementExampleAsync();
        Console.WriteLine();

        Console.WriteLine("3. Admin Operations Example");
        Console.WriteLine("=" * 40);
        await AdminOperationsExampleAsync();
        Console.WriteLine();

        Console.WriteLine("4. Bulk Operations Example");
        Console.WriteLine("=" * 40);
        await BulkOperationsExampleAsync();
        Console.WriteLine();

        Console.WriteLine("Examples completed!");
    }

    public void Dispose()
    {
        _sdk?.Dispose();
    }
}

/// <summary>
/// Entry point for running the examples
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        var example = new BasicExample();
        
        try
        {
            await example.RunAllExamplesAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Fatal error: {ex.Message}");
            Environment.Exit(1);
        }
        finally
        {
            example.Dispose();
        }
    }
}