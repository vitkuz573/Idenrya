using Microsoft.AspNetCore.Identity;

namespace Idenrya.Server.Models;

public sealed class ApplicationUser : IdentityUser
{
    public string GivenName { get; set; } = string.Empty;

    public string FamilyName { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;
}
