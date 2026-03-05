using System.ComponentModel.DataAnnotations;

namespace Idenrya.Server.Models.Admin;

public sealed class CreateOpenIdScopeRequest
{
    [Required]
    public string Name { get; set; } = string.Empty;

    public string? DisplayName { get; set; }

    public List<string> Resources { get; set; } = [];
}

public sealed class OpenIdScopeResponse
{
    public string Name { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public List<string> Resources { get; set; } = [];
}
