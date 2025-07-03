using System.Text.Json;
using System.Text.Json.Serialization;

namespace IrisIdentitySDK.Models;

/// <summary>
/// Base user model for identity operations
/// </summary>
public class User
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("created_at")]
    public DateTime? CreatedAt { get; set; }

    [JsonPropertyName("updated_at")]
    public DateTime? UpdatedAt { get; set; }

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("attrs")]
    public JsonElement? Attrs { get; set; }

    [JsonIgnore]
    public string? Password { get; set; }
}

/// <summary>
/// Token response from authentication operations
/// </summary>
public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; set; }

    public DateTime? Expiry 
    { 
        get => ExpiresIn.HasValue ? DateTime.UtcNow.AddSeconds(ExpiresIn.Value) : null;
    }
}

/// <summary>
/// Client token claims
/// </summary>
public class ClientTokenClaims
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("client_secret")]
    public string ClientSecret { get; set; } = string.Empty;

    [JsonPropertyName("scopes")]
    public string[]? Scopes { get; set; }

    [JsonPropertyName("iss")]
    public string Issuer { get; set; } = string.Empty;

    [JsonPropertyName("aud")]
    public string Audience { get; set; } = string.Empty;

    [JsonPropertyName("exp")]
    public long Expiration { get; set; }

    [JsonPropertyName("iat")]
    public long IssuedAt { get; set; }
}

/// <summary>
/// User attribute definition from schema
/// </summary>
public class UserAttribute
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("params")]
    public string[]? Params { get; set; }

    [JsonPropertyName("indexed")]
    public bool Indexed { get; set; }
}