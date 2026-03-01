using Microsoft.AspNetCore.Identity;

namespace Idenrya.Server.Models;

public sealed class ApplicationUser : IdentityUser
{
    public string GivenName { get; set; } = "Conformance";

    public string FamilyName { get; set; } = "User";

    public string Address { get; set; } = "123 Test Street, Test City";
}
