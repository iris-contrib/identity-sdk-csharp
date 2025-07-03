# Iris Identity SDK for .NET

A comprehensive C# SDK for integrating with the Iris Identity Server, providing JWT-based authentication, user management, and OAuth2/OIDC support.

## Features

- 🔐 **JWT Authentication**: Secure token-based authentication
- 👥 **User Management**: Complete CRUD operations for users
- 🛡️ **Password Security**: AES-GCM encryption for password transmission
- ✅ **Password Validation**: Configurable password strength levels
- 🔧 **Admin Operations**: Administrative user management functions
- 🌐 **HTTP Client**: Built-in HTTP client with proper error handling
- 🧪 **Token Verification**: Local and server-side token validation
- 📊 **Pagination**: Support for paginated user queries
- 🔍 **Filtering**: Advanced user filtering capabilities

## Installation

### Package Manager
```bash
Install-Package IrisIdentitySDK
```

### .NET CLI
```bash
dotnet add package IrisIdentitySDK
```

### PackageReference
```xml
<PackageReference Include="IrisIdentitySDK" Version="1.0.0" />
```

## Quick Start

### 1. Basic Setup

```csharp
using IrisIdentitySDK;
using IrisIdentitySDK.Models;

// Define your user model
public class MyUser : User
{
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;
    
    [JsonPropertyName("firstname")]
    public string FirstName { get; set; } = string.Empty;
    
    [JsonPropertyName("lastname")]
    public string LastName { get; set; } = string.Empty;
}

// Configure the SDK
var options = new IdentityOptions
{
    BaseURL = "https://your-identity-server.com",
    Token = "your-client-token",
    EncryptionKey = "your-32-char-encryption-key",
    PasswordStrengthLevel = PasswordStrengthLevel.Medium
};

// Initialize the SDK
var sdk = new IdentitySDK<MyUser>(options);
await sdk.InitializeAsync();
```

### 2. User Authentication

```csharp
try
{
    // Sign in a user
    var token = await sdk.UserSigninAsync("user@example.com", "password123");
    
    Console.WriteLine($"Access Token: {token.AccessToken}");
    Console.WriteLine($"Expires: {token.Expiry}");
}
catch (HttpRequestException ex)
{
    Console.WriteLine($"Authentication failed: {ex.Message}");
}
```

### 3. User Registration

```csharp
var newUser = new MyUser
{
    Username = "johndoe",
    Email = "john@example.com",
    FirstName = "John",
    LastName = "Doe"
};

try
{
    var token = await sdk.AdminUserSignupAsync(newUser, "SecurePassword123!");
    Console.WriteLine("User registered successfully!");
}
catch (ArgumentException ex)
{
    Console.WriteLine($"Validation error: {ex.Message}");
}
```

## Configuration

### appsettings.json

```json
{
  "IdentityOptions": {
    "BaseURL": "https://identity.example.com",
    "Token": "your-client-token",
    "EncryptionKey": "14be763a0cd7b7b98d48c3e808bfaf84",
    "PasswordStrengthLevel": "Medium"
  }
}
```

### Dependency Injection

```csharp
// Program.cs or Startup.cs
services.Configure<IdentityOptions>(configuration.GetSection("IdentityOptions"));
services.AddHttpClient<IdentitySDK<MyUser>>();
services.AddTransient<IdentitySDK<MyUser>>();
```

## Advanced Usage

### User Management

```csharp
// Get user schema
var schema = await sdk.AdminGetUserSchemaAsync();
foreach (var attr in schema)
{
    Console.WriteLine($"Attribute: {attr.Name}, Type: {attr.Type}");
}

// Search users with filtering
var pageOptions = new PageOptions { Page = 1, Size = 10 };
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
            Value = "%@example.com%"
        }
    }
};

var users = await sdk.AdminListUsersAsync(pageOptions, filter);
Console.WriteLine($"Found {users.Total} users");
```

### Token Operations

```csharp
// Verify token locally
try
{
    var user = await sdk.VerifyTokenAsync(accessToken);
    Console.WriteLine($"Token valid for user: {user.Username}");
}
catch (SecurityTokenValidationException ex)
{
    Console.WriteLine($"Token validation failed: {ex.Message}");
}

// Server-side token introspection
var userFromServer = await sdk.TokenIntrospectAsync(accessToken);

// Client-side token introspection (no verification)
var unverifiedUser = IdentitySDK<MyUser>.IntrospectToken(accessToken);
```

### Password Management

```csharp
// Reset user password
var resetRequest = new AdminResetUserPasswordRequest
{
    Identifier = "user@example.com",
    Password = "NewSecurePassword123!"
};

bool success = await sdk.AdminResetUserPasswordAsync(resetRequest);
if (success)
{
    Console.WriteLine("Password reset successfully");
}
```

### User Operations

```csharp
// Delete user (soft delete)
var deleteRequest = new AdminDeleteUserRequest
{
    Identifier = "user@example.com",
    Soft = true
};

bool deleted = await sdk.AdminDeleteUserAsync(deleteRequest);

// Restore deleted user
var restoreRequest = new AdminRestoreUserRequest
{
    Identifier = "user@example.com"
};

bool restored = await sdk.AdminRestoreUserAsync(restoreRequest);
```

## Error Handling

```csharp
try
{
    var token = await sdk.UserSigninAsync(username, password);
}
catch (HttpRequestException ex) when (ex.Message.Contains("401"))
{
    // Invalid credentials
    Console.WriteLine("Invalid username or password");
}
catch (HttpRequestException ex) when (ex.Message.Contains("403"))
{
    // Account locked or disabled
    Console.WriteLine("Account is locked or disabled");
}
catch (HttpRequestException ex) when (ex.Message.Contains("429"))
{
    // Rate limited
    Console.WriteLine("Too many requests, please try again later");
}
catch (ArgumentException ex)
{
    // Validation error
    Console.WriteLine($"Validation error: {ex.Message}");
}
catch (Exception ex)
{
    // General error
    Console.WriteLine($"Unexpected error: {ex.Message}");
}
```

## Password Validation

The SDK supports multiple password strength levels:

```csharp
using IrisIdentitySDK.Security;

// Validate password strength
var result = PasswordValidator.ValidatePassword("MyPassword123!", PasswordStrengthLevel.Strong);
if (!result.IsValid)
{
    Console.WriteLine($"Password validation failed: {result.Message}");
}

// Available strength levels:
// - VeryWeak: Minimal requirements
// - Weak: 6+ characters
// - Medium: 8+ chars, mixed case, numbers
// - Strong: 10+ chars, mixed case, numbers, special chars
// - VeryStrong: 12+ chars, multiple of each type, no common patterns
```

## Security Features

### Password Encryption

```csharp
using IrisIdentitySDK.Security;

// Encrypt password for transmission
string encrypted = PasswordEncryption.EncryptPassword("mypassword", encryptionKey);

// Each encryption produces different output for security
string encrypted1 = PasswordEncryption.EncryptPassword("same", key);
string encrypted2 = PasswordEncryption.EncryptPassword("same", key);
// encrypted1 != encrypted2 (but both decrypt to "same")
```

### Token Security

- JWT tokens are verified using RS256/EdDSA algorithms
- Public keys are automatically loaded from JWKS endpoint
- Token validation includes issuer, audience, and expiration checks
- Clock skew tolerance of 5 minutes

## ASP.NET Core Integration

### Authentication Middleware

```csharp
public class IdentityAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IdentitySDK<MyUser> _sdk;

    public IdentityAuthenticationMiddleware(RequestDelegate next, IdentitySDK<MyUser> sdk)
    {
        _next = next;
        _sdk = sdk;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"]
            .FirstOrDefault()?.Split(" ").Last();

        if (!string.IsNullOrEmpty(token))
        {
            try
            {
                var user = await _sdk.VerifyTokenAsync(token);
                context.Items["User"] = user;
            }
            catch
            {
                // Token validation failed
                context.Response.StatusCode = 401;
                return;
            }
        }

        await _next(context);
    }
}

// Register middleware
app.UseMiddleware<IdentityAuthenticationMiddleware>();
```

### Controller Integration

```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IdentitySDK<MyUser> _sdk;

    public UsersController(IdentitySDK<MyUser> sdk)
    {
        _sdk = sdk;
    }

    [HttpPost("signin")]
    public async Task<IActionResult> Signin([FromBody] SigninRequest request)
    {
        try
        {
            var token = await _sdk.UserSigninAsync(request.Username, request.Password);
            return Ok(new { token = token.AccessToken, expires = token.Expiry });
        }
        catch (HttpRequestException)
        {
            return Unauthorized(new { error = "Invalid credentials" });
        }
    }

    [HttpGet("profile")]
    [Authorize]
    public IActionResult GetProfile()
    {
        var user = HttpContext.Items["User"] as MyUser;
        return Ok(user);
    }
}
```

## Best Practices

### 1. Configuration Management

```csharp
// Use configuration providers
services.Configure<IdentityOptions>(configuration.GetSection("Identity"));

// Validate configuration at startup
services.AddOptions<IdentityOptions>()
    .Bind(configuration.GetSection("Identity"))
    .ValidateDataAnnotations()
    .ValidateOnStart();
```

### 2. HTTP Client Management

```csharp
// Use IHttpClientFactory for better connection management
services.AddHttpClient<IdentitySDK<MyUser>>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});
```

### 3. Logging

```csharp
// Enable logging for debugging
services.AddLogging(builder =>
{
    builder.AddConsole();
    builder.SetMinimumLevel(LogLevel.Information);
});

var sdk = new IdentitySDK<MyUser>(options, httpClient, logger);
```

### 4. Async/Await Patterns

```csharp
// Always use ConfigureAwait(false) in library code
var token = await sdk.UserSigninAsync(username, password).ConfigureAwait(false);

// Use cancellation tokens for long-running operations
var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;
var users = await sdk.AdminListUsersAsync(pageOptions, filter, cancellationToken);
```

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid request data |
| 401 | Unauthorized - Invalid credentials |
| 403 | Forbidden - Account locked/disabled |
| 404 | Not Found - User not found |
| 409 | Conflict - Username already exists |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error - Server error |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- Documentation: [Iris Framework Docs](https://iris-go.com)
- Issues: [GitHub Issues](https://github.com/kataras/iris/issues)
- Community: [Chat](https://chat.iris-go.com)