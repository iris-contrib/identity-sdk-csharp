using System.Text.Json.Serialization;

namespace IrisIdentitySDK.Models;

/// <summary>
/// Request model for admin user signin
/// </summary>
public class AdminUserSigninRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
}

/// <summary>
/// Request model for admin user deletion
/// </summary>
public class AdminDeleteUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;

    [JsonPropertyName("soft")]
    public bool Soft { get; set; } = false;
}

/// <summary>
/// Request model for admin user restoration
/// </summary>
public class AdminRestoreUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
}

/// <summary>
/// Request model for admin password reset
/// </summary>
public class AdminResetUserPasswordRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Token introspection request
/// </summary>
public class TokenIntrospectRequest
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
}

/// <summary>
/// Page options for listing operations
/// </summary>
public class PageOptions
{
    public int Page { get; set; } = 1;
    public int Size { get; set; } = 10;
}

/// <summary>
/// Filter term for user queries
/// </summary>
public class FilterTerm
{
    [JsonPropertyName("logic")]
    public string? Logic { get; set; }

    [JsonPropertyName("field")]
    public string Field { get; set; } = string.Empty;

    [JsonPropertyName("operator")]
    public string Operator { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// User filter options for queries
/// </summary>
public class UserFilterOptions
{
    [JsonPropertyName("sort")]
    public string? Sort { get; set; }

    [JsonPropertyName("sort_descending")]
    public bool SortDescending { get; set; } = false;

    [JsonPropertyName("include_deleted")]
    public bool IncludeDeleted { get; set; } = false;

    [JsonPropertyName("terms")]
    public FilterTerm[]? Terms { get; set; }
}

/// <summary>
/// Paginated response wrapper
/// </summary>
public class PagedResponse<T>
{
    [JsonPropertyName("items")]
    public T[] Items { get; set; } = Array.Empty<T>();

    [JsonPropertyName("total")]
    public long Total { get; set; }

    [JsonPropertyName("page")]
    public int Page { get; set; }

    [JsonPropertyName("size")]
    public int Size { get; set; }

    [JsonPropertyName("pages")]
    public int Pages { get; set; }
}

/// <summary>
/// Count response for bulk operations
/// </summary>
public class CountResponse<T>
{
    [JsonPropertyName("count")]
    public T Count { get; set; } = default!;
}