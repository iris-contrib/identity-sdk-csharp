using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using IrisIdentitySDK.Models;
using IrisIdentitySDK.Security;

namespace IrisIdentitySDK;

/// <summary>
/// Main SDK class for Iris Identity Server integration
/// </summary>
public class IdentitySDK<T> : IDisposable where T : User, new()
{
    private readonly IdentityOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<IdentitySDK<T>>? _logger;
    private ClientTokenClaims? _claims;
    private JsonWebKeySet? _jwks;

    /// <summary>
    /// Client token claims from the authenticated client
    /// </summary>
    public ClientTokenClaims? Claims => _claims;

    /// <summary>
    /// HTTP client for API calls
    /// </summary>
    public HttpClient HttpClient => _httpClient;

    /// <summary>
    /// Header name for client token authentication
    /// </summary>
    public const string ClientTokenHeader = "X-Token";

    /// <summary>
    /// Initializes a new instance of the IdentitySDK
    /// </summary>
    /// <param name="options">Configuration options</param>
    /// <param name="httpClient">Optional HTTP client (will create default if not provided)</param>
    /// <param name="logger">Optional logger</param>
    public IdentitySDK(IdentityOptions options, HttpClient? httpClient = null, ILogger<IdentitySDK<T>>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;

        ValidateOptions();

        _httpClient = httpClient ?? new HttpClient();
        _httpClient.BaseAddress = new Uri(_options.BaseURL);
        _httpClient.DefaultRequestHeaders.Add(ClientTokenHeader, _options.Token);
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    /// <summary>
    /// Initializes the SDK by loading public keys and verifying the client token
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the initialization operation</returns>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await LoadPublicKeysAsync(cancellationToken);
        await VerifyClientTokenAsync(cancellationToken);
    }

    /// <summary>
    /// Signs in a user with username and password
    /// </summary>
    /// <param name="username">Username or email</param>
    /// <param name="password">Plain text password</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token response</returns>
    public async Task<TokenResponse> UserSigninAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username))
            throw new ArgumentException("Username cannot be empty", nameof(username));
        
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        var encryptedPassword = PasswordEncryption.EncryptPassword(password, _options.EncryptionKey);

        var requestData = new
        {
            grant_type = "password",
            username = username,
            password = encryptedPassword,
            client_id = _claims?.ClientId,
            client_secret = _claims?.ClientSecret
        };

        var response = await SendPostRequestAsync<TokenResponse>("/oauth2/token", requestData, cancellationToken);
        return response;
    }

    /// <summary>
    /// Signs in a user using admin privileges (no password required)
    /// </summary>
    /// <param name="request">Admin signin request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token response</returns>
    public async Task<TokenResponse> AdminUserSigninAsync(AdminUserSigninRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var response = await SendPostRequestAsync<TokenResponse>("/u/signin", request, cancellationToken);
        return response;
    }

    /// <summary>
    /// Signs up a new user (admin operation)
    /// </summary>
    /// <param name="user">User data</param>
    /// <param name="password">Plain text password</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token response</returns>
    public async Task<TokenResponse> AdminUserSignupAsync(T user, string password, CancellationToken cancellationToken = default)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user));
        
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty", nameof(password));

        // Validate password strength
        var passwordValidation = PasswordValidator.ValidatePassword(password, _options.PasswordStrengthLevel);
        if (!passwordValidation.IsValid)
        {
            throw new ArgumentException($"Password validation failed: {passwordValidation.Message}");
        }

        var encryptedPassword = PasswordEncryption.EncryptPassword(password, _options.EncryptionKey);

        // Merge user data with encrypted password
        var userJson = JsonSerializer.Serialize(user);
        var passwordJson = JsonSerializer.Serialize(new { password = encryptedPassword });
        
        var mergedRequest = MergeJsonObjects(userJson, passwordJson);

        var response = await SendPostRequestAsync<TokenResponse>("/u/signup", mergedRequest, cancellationToken);
        return response;
    }

    /// <summary>
    /// Gets the user schema from the identity server
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Array of user attributes</returns>
    public async Task<UserAttribute[]> AdminGetUserSchemaAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendGetRequestAsync<UserAttribute[]>("/u/schema", cancellationToken);
        return response;
    }

    /// <summary>
    /// Deletes a user (admin operation)
    /// </summary>
    /// <param name="request">Delete user request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if user was deleted, false otherwise</returns>
    public async Task<bool> AdminDeleteUserAsync(AdminDeleteUserRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Delete, "/u")
            {
                Content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json")
            }, 
            cancellationToken);

        return response.StatusCode == System.Net.HttpStatusCode.NoContent;
    }

    /// <summary>
    /// Restores a soft-deleted user (admin operation)
    /// </summary>
    /// <param name="request">Restore user request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if user was restored, false otherwise</returns>
    public async Task<bool> AdminRestoreUserAsync(AdminRestoreUserRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/u/restore")
            {
                Content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json")
            }, 
            cancellationToken);

        return response.StatusCode == System.Net.HttpStatusCode.NoContent;
    }

    /// <summary>
    /// Resets a user's password (admin operation)
    /// </summary>
    /// <param name="request">Password reset request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if password was reset, false otherwise</returns>
    public async Task<bool> AdminResetUserPasswordAsync(AdminResetUserPasswordRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        // Validate password strength
        var passwordValidation = PasswordValidator.ValidatePassword(request.Password, _options.PasswordStrengthLevel);
        if (!passwordValidation.IsValid)
        {
            throw new ArgumentException($"Password validation failed: {passwordValidation.Message}");
        }

        var encryptedPassword = PasswordEncryption.EncryptPassword(request.Password, _options.EncryptionKey);

        // First, request password reset token
        var tokenRequest = new { identifier = request.Identifier };
        var resetToken = await SendPostRequestAsync<string>("/u/request-password-reset", tokenRequest, cancellationToken);

        // Then, confirm password reset with new password
        var confirmRequest = new 
        { 
            token = resetToken,
            new_password = encryptedPassword
        };

        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "/u/confirm-password-reset")
            {
                Content = new StringContent(JsonSerializer.Serialize(confirmRequest), Encoding.UTF8, "application/json")
            }, 
            cancellationToken);

        return response.StatusCode == System.Net.HttpStatusCode.NoContent;
    }

    /// <summary>
    /// Lists users with pagination and filtering (admin operation)
    /// </summary>
    /// <param name="pageOptions">Pagination options</param>
    /// <param name="filter">Filter options</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Paginated user response</returns>
    public async Task<PagedResponse<T>> AdminListUsersAsync(PageOptions pageOptions, UserFilterOptions? filter = null, CancellationToken cancellationToken = default)
    {
        if (pageOptions == null)
            throw new ArgumentNullException(nameof(pageOptions));

        var queryParams = $"?page={pageOptions.Page}&size={pageOptions.Size}";
        var url = $"/u/list{queryParams}";

        var response = await SendPostRequestAsync<PagedResponse<T>>(url, filter, cancellationToken);
        return response;
    }

    /// <summary>
    /// Updates multiple users (admin operation)
    /// </summary>
    /// <param name="users">Users to update</param>
    /// <param name="onlyColumns">Specific columns to update (optional)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Count of updated users</returns>
    public async Task<CountResponse<long>> AdminUpdateUsersAsync(T[] users, string[]? onlyColumns = null, CancellationToken cancellationToken = default)
    {
        if (users == null)
            throw new ArgumentNullException(nameof(users));

        var url = "/u";
        if (onlyColumns?.Length > 0)
        {
            var columns = string.Join("&", onlyColumns.Select(c => $"columns={Uri.EscapeDataString(c)}"));
            url += $"?{columns}";
        }

        var response = await SendPutRequestAsync<CountResponse<long>>(url, users, cancellationToken);
        return response;
    }

    /// <summary>
    /// Introspects a token by making a server call
    /// </summary>
    /// <param name="accessToken">Access token to introspect</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User data from token</returns>
    public async Task<T> TokenIntrospectAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(accessToken))
            throw new ArgumentException("Access token cannot be empty", nameof(accessToken));

        var request = new TokenIntrospectRequest { AccessToken = accessToken };
        var response = await SendPostRequestAsync<T>("/oauth2/token/introspect", request, cancellationToken);
        return response;
    }

    /// <summary>
    /// Verifies a JWT token locally using cached public keys
    /// </summary>
    /// <param name="token">JWT token to verify</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User data from verified token</returns>
    public async Task<T> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("Token cannot be empty", nameof(token));

        if (_jwks == null)
            await LoadPublicKeysAsync(cancellationToken);

        var handler = new JsonWebTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = _jwks!.Keys,
            ValidateIssuer = true,
            ValidIssuer = _claims?.Issuer,
            ValidateAudience = true,
            ValidAudience = _claims?.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var result = await handler.ValidateTokenAsync(token, validationParameters);
        if (!result.IsValid)
        {
            throw new SecurityTokenValidationException("Token validation failed", result.Exception);
        }

        var claims = result.Claims;
        var userJson = JsonSerializer.Serialize(claims);
        var user = JsonSerializer.Deserialize<T>(userJson);
        
        return user ?? throw new InvalidOperationException("Failed to deserialize user from token claims");
    }

    /// <summary>
    /// Introspects a token without verification (for debugging purposes)
    /// </summary>
    /// <param name="token">JWT token to introspect</param>
    /// <returns>User data from token (unverified)</returns>
    public static T IntrospectToken(string token)
    {
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("Token cannot be empty", nameof(token));

        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadJwtToken(token);
        
        var claimsDict = jsonToken.Claims.ToDictionary(c => c.Type, c => c.Value);
        var userJson = JsonSerializer.Serialize(claimsDict);
        var user = JsonSerializer.Deserialize<T>(userJson);
        
        return user ?? throw new InvalidOperationException("Failed to deserialize user from token claims");
    }

    private async Task LoadPublicKeysAsync(CancellationToken cancellationToken)
    {
        try
        {
            var jwksUri = $"{_options.BaseURL.TrimEnd('/')}/.well-known/jwks.json";
            var response = await _httpClient.GetStringAsync(jwksUri, cancellationToken);
            _jwks = new JsonWebKeySet(response);
            
            _logger?.LogInformation("Successfully loaded {KeyCount} public keys from JWKS endpoint", _jwks.Keys.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load public keys from JWKS endpoint");
            throw new InvalidOperationException("Failed to load public keys from identity server", ex);
        }
    }

    private async Task VerifyClientTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_jwks == null)
                await LoadPublicKeysAsync(cancellationToken);

            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = _jwks!.Keys,
                ValidateLifetime = true,
                ValidateIssuer = false, // Client tokens may have different issuer
                ValidateAudience = false,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var result = await handler.ValidateTokenAsync(_options.Token, validationParameters);
            if (!result.IsValid)
            {
                throw new SecurityTokenValidationException("Client token validation failed", result.Exception);
            }

            var claimsJson = JsonSerializer.Serialize(result.Claims);
            _claims = JsonSerializer.Deserialize<ClientTokenClaims>(claimsJson);
            
            _logger?.LogInformation("Client token verified successfully for client {ClientId}", _claims?.ClientId);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Client token verification failed");
            throw new UnauthorizedAccessException("Invalid client token", ex);
        }
    }

    private void ValidateOptions()
    {
        if (string.IsNullOrEmpty(_options.BaseURL))
            throw new ArgumentException("BaseURL is required", nameof(_options.BaseURL));
        
        if (string.IsNullOrEmpty(_options.Token))
            throw new ArgumentException("Token is required", nameof(_options.Token));
        
        if (string.IsNullOrEmpty(_options.EncryptionKey))
            throw new ArgumentException("EncryptionKey is required", nameof(_options.EncryptionKey));

        if (!PasswordEncryption.IsValidEncryptionKey(_options.EncryptionKey))
            throw new ArgumentException("EncryptionKey format is invalid", nameof(_options.EncryptionKey));

        if (!Uri.TryCreate(_options.BaseURL, UriKind.Absolute, out _))
            throw new ArgumentException("BaseURL must be a valid absolute URI", nameof(_options.BaseURL));
    }

    private async Task<TResponse> SendGetRequestAsync<TResponse>(string endpoint, CancellationToken cancellationToken)
    {
        var response = await _httpClient.GetAsync(endpoint, cancellationToken);
        await EnsureSuccessStatusCodeAsync(response);
        
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonSerializer.Deserialize<TResponse>(content) ?? throw new InvalidOperationException("Failed to deserialize response");
    }

    private async Task<TResponse> SendPostRequestAsync<TResponse>(string endpoint, object? requestData, CancellationToken cancellationToken)
    {
        var json = requestData != null ? JsonSerializer.Serialize(requestData) : "{}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        
        var response = await _httpClient.PostAsync(endpoint, content, cancellationToken);
        await EnsureSuccessStatusCodeAsync(response);
        
        var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonSerializer.Deserialize<TResponse>(responseContent) ?? throw new InvalidOperationException("Failed to deserialize response");
    }

    private async Task<TResponse> SendPutRequestAsync<TResponse>(string endpoint, object requestData, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(requestData);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        
        var response = await _httpClient.PutAsync(endpoint, content, cancellationToken);
        await EnsureSuccessStatusCodeAsync(response);
        
        var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonSerializer.Deserialize<TResponse>(responseContent) ?? throw new InvalidOperationException("Failed to deserialize response");
    }

    private static async Task EnsureSuccessStatusCodeAsync(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"API request failed with status {response.StatusCode}: {errorContent}");
        }
    }

    private static object MergeJsonObjects(string json1, string json2)
    {
        var obj1 = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json1);
        var obj2 = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json2);
        
        var merged = new Dictionary<string, JsonElement>();
        
        if (obj1 != null)
        {
            foreach (var kvp in obj1)
                merged[kvp.Key] = kvp.Value;
        }
        
        if (obj2 != null)
        {
            foreach (var kvp in obj2)
                merged[kvp.Key] = kvp.Value;
        }
        
        return merged;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        GC.SuppressFinalize(this);
    }
}