using System.ComponentModel.DataAnnotations;

namespace Idenrya.Server.Models.Admin;

public sealed class CreateOpenIdClientRequest
{
    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    [Required]
    public string DisplayName { get; set; } = string.Empty;

    [MinLength(1)]
    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public bool PublicClient { get; set; }

    public bool RequirePkce { get; set; } = true;

    public string ConsentType { get; set; } = "explicit";
}

public sealed class UpdateOpenIdClientRequest
{
    public string? ClientSecret { get; set; }

    [Required]
    public string DisplayName { get; set; } = string.Empty;

    [MinLength(1)]
    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public bool PublicClient { get; set; }

    public bool RequirePkce { get; set; } = true;

    public string ConsentType { get; set; } = "explicit";
}

public sealed class OpenIdClientResponse
{
    public string Id { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string ClientType { get; set; } = string.Empty;

    public string ConsentType { get; set; } = string.Empty;

    public bool RequirePkce { get; set; }

    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public List<string> Scopes { get; set; } = [];
}
