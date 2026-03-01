namespace Idenrya.Server.Models;

public sealed class ConformanceOptions
{
    public const string SectionName = "Conformance";

    public string Issuer { get; set; } = "https://oidcc-provider:3000";

    public string CallbackBaseUrl { get; set; } = "https://nginx:8443/test/a/idenrya-basic";

    public string? CallbackBaseUrl2 { get; set; }

    public string ClientId { get; set; } = "idenrya-basic-client";

    public string ClientSecret { get; set; } = "idenrya-basic-secret";

    public string Client2Id { get; set; } = "idenrya-basic-client-2";

    public string Client2Secret { get; set; } = "idenrya-basic-secret-2";

    public ConformanceSeedOptions Seed { get; set; } = new();

    public string RedirectUri => $"{CallbackBaseUrl.TrimEnd('/')}/callback";

    public string RedirectUri2 => $"{(CallbackBaseUrl2 ?? CallbackBaseUrl).TrimEnd('/')}/callback";

    public IReadOnlyList<ConformanceClientOptions> GetSeedClients()
    {
        var configuredClients = Seed.Clients
            .Where(static client => !string.IsNullOrWhiteSpace(client.ClientId))
            .Select(client =>
            {
                client.RedirectUris = client.RedirectUris
                    .Where(static redirectUri => !string.IsNullOrWhiteSpace(redirectUri))
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
                return client;
            })
            .Where(static client => client.RedirectUris.Count > 0)
            .ToList();

        if (configuredClients.Count > 0)
        {
            return configuredClients;
        }

        return
        [
            new ConformanceClientOptions
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                DisplayName = "Idenrya conformance client #1",
                RedirectUris = [RedirectUri]
            },
            new ConformanceClientOptions
            {
                ClientId = Client2Id,
                ClientSecret = Client2Secret,
                DisplayName = "Idenrya conformance client #2",
                RedirectUris = [RedirectUri2]
            }
        ];
    }

    public IReadOnlyList<ConformanceUserOptions> GetSeedUsers()
    {
        var configuredUsers = Seed.Users
            .Where(static user => !string.IsNullOrWhiteSpace(user.UserName))
            .ToList();

        if (configuredUsers.Count > 0)
        {
            return configuredUsers;
        }

        return
        [
            new ConformanceUserOptions
            {
                UserName = "foo",
                Password = "bar",
                Email = "foo@idenrya.local",
                EmailConfirmed = true,
                PhoneNumber = "+1-555-0100",
                PhoneNumberConfirmed = true,
                GivenName = "Conformance",
                FamilyName = "User",
                Address = "123 Test Street, Test City",
                Claims = new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["middle_name"] = "Q",
                    ["nickname"] = "foo",
                    ["profile"] = "https://idenrya.local/users/foo",
                    ["picture"] = "https://idenrya.local/assets/foo.png",
                    ["website"] = "https://idenrya.local",
                    ["gender"] = "unspecified",
                    ["birthdate"] = "1970-01-01",
                    ["zoneinfo"] = "America/New_York",
                    ["locale"] = "en-US",
                    ["updated_at"] = "1700000000"
                }
            }
        ];
    }

    public IEnumerable<string> GetKnownRedirectUris()
    {
        foreach (var redirectUri in GetSeedClients()
                     .SelectMany(static client => client.RedirectUris)
                     .Distinct(StringComparer.Ordinal))
        {
            yield return redirectUri;
        }
    }
}

public sealed class ConformanceSeedOptions
{
    public List<ConformanceClientOptions> Clients { get; set; } = [];

    public List<ConformanceUserOptions> Users { get; set; } = [];
}

public sealed class ConformanceClientOptions
{
    public string ClientId { get; set; } = string.Empty;

    public string ClientSecret { get; set; } = string.Empty;

    public string DisplayName { get; set; } = "Idenrya client";

    public List<string> RedirectUris { get; set; } = [];

    public List<string> Scopes { get; set; } =
    [
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Address,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Phone,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess
    ];
}

public sealed class ConformanceUserOptions
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

    public Dictionary<string, string?> Claims { get; set; } = new(StringComparer.Ordinal);
}
