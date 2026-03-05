using System.Text.Json;
using System.Text.Json.Serialization;

namespace Idenrya.Server.Models;

public sealed class OpenIdDynamicClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; set; } = [];

    [JsonPropertyName("request_uris")]
    public List<string> RequestUris { get; set; } = [];

    [JsonPropertyName("grant_types")]
    public List<string> GrantTypes { get; set; } = [];

    [JsonPropertyName("response_types")]
    public List<string> ResponseTypes { get; set; } = [];

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    [JsonPropertyName("application_type")]
    public string? ApplicationType { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("id_token_signed_response_alg")]
    public string? IdTokenSignedResponseAlg { get; set; }

    [JsonPropertyName("contacts")]
    public List<string> Contacts { get; set; } = [];

    [JsonPropertyName("jwks")]
    public JsonElement? Jwks { get; set; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }
}

public sealed class OpenIdDynamicClientRegistrationResponse
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("client_secret")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("client_id_issued_at")]
    public long ClientIdIssuedAt { get; set; }

    [JsonPropertyName("client_secret_expires_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? ClientSecretExpiresAt { get; set; }

    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; set; } = [];

    [JsonPropertyName("request_uris")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? RequestUris { get; set; }

    [JsonPropertyName("grant_types")]
    public List<string> GrantTypes { get; set; } = [];

    [JsonPropertyName("response_types")]
    public List<string> ResponseTypes { get; set; } = [];

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod { get; set; } = "client_secret_basic";

    [JsonPropertyName("client_name")]
    public string ClientName { get; set; } = string.Empty;

    [JsonPropertyName("application_type")]
    public string ApplicationType { get; set; } = "web";

    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; set; }

    [JsonPropertyName("id_token_signed_response_alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdTokenSignedResponseAlg { get; set; }

    [JsonPropertyName("contacts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Contacts { get; set; }

    [JsonPropertyName("registration_client_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationClientUri { get; set; }

    [JsonPropertyName("registration_access_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationAccessToken { get; set; }
}
