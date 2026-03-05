using System.ComponentModel.DataAnnotations;

namespace Idenrya.Server.Models.Admin;

public sealed class CreateOpenIdUserRequest
{
    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public bool EmailConfirmed { get; set; } = true;

    public string PhoneNumber { get; set; } = string.Empty;

    public bool PhoneNumberConfirmed { get; set; } = true;

    public string GivenName { get; set; } = string.Empty;

    public string FamilyName { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = [];

    public Dictionary<string, string?> Claims { get; set; } = new(StringComparer.Ordinal);
}

public sealed class UpdateOpenIdUserRequest
{
    public string? Password { get; set; }

    public string Email { get; set; } = string.Empty;

    public bool EmailConfirmed { get; set; } = true;

    public string PhoneNumber { get; set; } = string.Empty;

    public bool PhoneNumberConfirmed { get; set; } = true;

    public string GivenName { get; set; } = string.Empty;

    public string FamilyName { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = [];

    public Dictionary<string, string?> Claims { get; set; } = new(StringComparer.Ordinal);
}

public sealed class OpenIdUserResponse
{
    public string Id { get; set; } = string.Empty;

    public string UserName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public bool EmailConfirmed { get; set; }

    public string PhoneNumber { get; set; } = string.Empty;

    public bool PhoneNumberConfirmed { get; set; }

    public string GivenName { get; set; } = string.Empty;

    public string FamilyName { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = [];

    public Dictionary<string, string> Claims { get; set; } = new(StringComparer.Ordinal);
}
