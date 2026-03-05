using System.ComponentModel.DataAnnotations;

namespace Idenrya.Server.Models.Admin;

public sealed class CreateOpenIdRoleRequest
{
    [Required]
    public string Name { get; set; } = string.Empty;
}

public sealed class OpenIdRoleResponse
{
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;
}
