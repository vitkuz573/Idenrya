namespace Idenrya.Server.Models;

public sealed class IdentityProviderOptions
{
    public const string SectionName = "IdentityProvider";

    public string? Issuer { get; set; }

    public IdentityProviderBootstrapOptions Bootstrap { get; set; } = new();

    public IdentityProviderCredentialsOptions Credentials { get; set; } = new();
}

public sealed class IdentityProviderCredentialsOptions
{
    public bool AllowDevelopmentCertificates { get; set; }

    public IdentityProviderCertificateOptions SigningCertificate { get; set; } = new();

    public IdentityProviderCertificateOptions EncryptionCertificate { get; set; } = new();
}

public sealed class IdentityProviderCertificateOptions
{
    public string? Path { get; set; }

    public string? Password { get; set; }
}

public sealed class IdentityProviderBootstrapOptions
{
    public bool Enabled { get; set; }

    public List<IdentityProviderClientOptions> Clients { get; set; } = [];

    public List<IdentityProviderUserOptions> Users { get; set; } = [];
}

public sealed class IdentityProviderClientOptions
{
    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    public string DisplayName { get; set; } = "Idenrya client";

    public List<string> RedirectUris { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public bool RequirePkce { get; set; }
}

public sealed class IdentityProviderUserOptions
{
    public string UserName { get; set; } = string.Empty;

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
