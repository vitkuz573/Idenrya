using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderClientService(
    IOpenIddictApplicationManager applicationManager,
    IIdentityProviderScopeService scopeService) : IIdentityProviderClientService
{
    public async Task<IReadOnlyList<OpenIdClientResponse>> ListAsync(CancellationToken cancellationToken = default)
    {
        var clients = new List<OpenIdClientResponse>();
        await foreach (var application in applicationManager.ListAsync(null, null, cancellationToken))
        {
            clients.Add(await BuildResponseAsync(application, cancellationToken));
        }

        return clients
            .OrderBy(static client => client.ClientId, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<OpenIdClientResponse?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var application = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        return application is null
            ? null
            : await BuildResponseAsync(application, cancellationToken);
    }

    public async Task<OpenIdClientResponse> CreateAsync(
        CreateOpenIdClientRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateClientId(request.ClientId);
        var normalizedScopes = scopeService.NormalizeClientScopes(request.Scopes);
        var normalized = NormalizeRequest(
            request.DisplayName,
            request.ClientSecret,
            request.RedirectUris,
            request.PostLogoutRedirectUris,
            normalizedScopes,
            request.PublicClient,
            request.RequirePkce,
            request.ConsentType);

        var existing = await applicationManager.FindByClientIdAsync(request.ClientId, cancellationToken);
        if (existing is not null)
        {
            throw new InvalidOperationException($"Client '{request.ClientId}' already exists.");
        }

        var descriptor = BuildDescriptor(request.ClientId, normalized);
        await applicationManager.CreateAsync(descriptor, cancellationToken);

        var created = await applicationManager.FindByClientIdAsync(request.ClientId, cancellationToken)
                      ?? throw new InvalidOperationException(
                          $"Client '{request.ClientId}' was created but cannot be retrieved.");

        return await BuildResponseAsync(created, cancellationToken);
    }

    public async Task<OpenIdClientResponse?> UpdateAsync(
        string clientId,
        UpdateOpenIdClientRequest request,
        CancellationToken cancellationToken = default)
    {
        ValidateClientId(clientId);
        var normalizedScopes = scopeService.NormalizeClientScopes(request.Scopes);
        var normalized = NormalizeRequest(
            request.DisplayName,
            request.ClientSecret,
            request.RedirectUris,
            request.PostLogoutRedirectUris,
            normalizedScopes,
            request.PublicClient,
            request.RequirePkce,
            request.ConsentType);

        var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
        {
            return null;
        }

        var descriptor = BuildDescriptor(clientId, normalized);
        await applicationManager.UpdateAsync(existing, descriptor, cancellationToken);

        return await BuildResponseAsync(existing, cancellationToken);
    }

    public async Task<bool> DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ValidateClientId(clientId);
        var existing = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
        {
            return false;
        }

        await applicationManager.DeleteAsync(existing, cancellationToken);
        return true;
    }

    public async Task UpsertBootstrapClientAsync(
        IdentityProviderClientOptions options,
        CancellationToken cancellationToken = default)
    {
        ValidateClientId(options.ClientId);
        var normalizedScopes = scopeService.NormalizeClientScopes(options.Scopes);
        var normalized = NormalizeRequest(
            options.DisplayName,
            options.ClientSecret,
            options.RedirectUris,
            [],
            normalizedScopes,
            publicClient: string.IsNullOrWhiteSpace(options.ClientSecret),
            requirePkce: options.RequirePkce,
            consentType: OpenIddictConstants.ConsentTypes.Implicit);

        var existing = await applicationManager.FindByClientIdAsync(options.ClientId, cancellationToken);
        var descriptor = BuildDescriptor(options.ClientId, normalized);

        if (existing is null)
        {
            await applicationManager.CreateAsync(descriptor, cancellationToken);
            return;
        }

        await applicationManager.UpdateAsync(existing, descriptor, cancellationToken);
    }

    private static void ValidateClientId(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("ClientId must be provided.", nameof(clientId));
        }
    }

    private static ClientConfiguration NormalizeRequest(
        string displayName,
        string? clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> normalizedScopes,
        bool publicClient,
        bool requirePkce,
        string consentType)
    {
        var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName)
            ? throw new ArgumentException("DisplayName must be provided.", nameof(displayName))
            : displayName.Trim();

        var normalizedRedirectUris = NormalizeUris(redirectUris, required: true, parameterName: nameof(redirectUris));
        var normalizedPostLogoutRedirectUris = NormalizeUris(
            postLogoutRedirectUris,
            required: false,
            parameterName: nameof(postLogoutRedirectUris));

        var normalizedConsentType = NormalizeConsentType(consentType);

        if (!publicClient && string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentException(
                "ClientSecret must be provided for confidential clients.",
                nameof(clientSecret));
        }

        return new ClientConfiguration
        {
            DisplayName = normalizedDisplayName,
            ClientSecret = string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret,
            RedirectUris = normalizedRedirectUris,
            PostLogoutRedirectUris = normalizedPostLogoutRedirectUris,
            Scopes = normalizedScopes.ToList(),
            PublicClient = publicClient,
            RequirePkce = requirePkce,
            ConsentType = normalizedConsentType
        };
    }

    private static List<string> NormalizeUris(
        IEnumerable<string> input,
        bool required,
        string parameterName)
    {
        var uris = input
            .Where(static uri => !string.IsNullOrWhiteSpace(uri))
            .Select(static uri => uri.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (required && uris.Count == 0)
        {
            throw new ArgumentException("At least one URI must be provided.", parameterName);
        }

        foreach (var uri in uris)
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
            {
                throw new ArgumentException($"URI '{uri}' is not a valid absolute URI.", parameterName);
            }
        }

        return uris;
    }

    private static string NormalizeConsentType(string consentType)
    {
        var normalized = (consentType ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "" or "explicit" => OpenIddictConstants.ConsentTypes.Explicit,
            "implicit" => OpenIddictConstants.ConsentTypes.Implicit,
            "external" => OpenIddictConstants.ConsentTypes.External,
            "systematic" => OpenIddictConstants.ConsentTypes.Systematic,
            _ => throw new ArgumentException(
                $"Unsupported consent type '{consentType}'. Allowed: explicit, implicit, external, systematic.",
                nameof(consentType))
        };
    }

    private static OpenIddictApplicationDescriptor BuildDescriptor(
        string clientId,
        ClientConfiguration configuration)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = configuration.PublicClient ? null : configuration.ClientSecret,
            DisplayName = configuration.DisplayName,
            ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
            ClientType = configuration.PublicClient
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = configuration.ConsentType
        };

        foreach (var redirectUri in configuration.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        foreach (var postLogoutRedirectUri in configuration.PostLogoutRedirectUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutRedirectUri));
        }

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        if (!configuration.PublicClient)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        }

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);

        foreach (var scope in configuration.Scopes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        if (configuration.RequirePkce)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        return descriptor;
    }

    private async Task<OpenIdClientResponse> BuildResponseAsync(
        object application,
        CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        var scopes = descriptor.Permissions
            .Where(static permission =>
                permission.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.Ordinal))
            .Select(static permission => permission[OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
            .OrderBy(static scope => scope, StringComparer.Ordinal)
            .ToList();

        return new OpenIdClientResponse
        {
            Id = await applicationManager.GetIdAsync(application, cancellationToken) ?? string.Empty,
            ClientId = descriptor.ClientId ?? string.Empty,
            DisplayName = descriptor.DisplayName ?? string.Empty,
            ClientType = descriptor.ClientType ?? string.Empty,
            ConsentType = descriptor.ConsentType ?? string.Empty,
            RequirePkce = descriptor.Requirements.Contains(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                StringComparer.Ordinal),
            RedirectUris = descriptor.RedirectUris
                .Select(static uri => uri.AbsoluteUri)
                .OrderBy(static uri => uri, StringComparer.Ordinal)
                .ToList(),
            PostLogoutRedirectUris = descriptor.PostLogoutRedirectUris
                .Select(static uri => uri.AbsoluteUri)
                .OrderBy(static uri => uri, StringComparer.Ordinal)
                .ToList(),
            Scopes = scopes
        };
    }

    private sealed class ClientConfiguration
    {
        public string DisplayName { get; init; } = string.Empty;

        public string? ClientSecret { get; init; }

        public List<string> RedirectUris { get; init; } = [];

        public List<string> PostLogoutRedirectUris { get; init; } = [];

        public List<string> Scopes { get; init; } = [];

        public bool PublicClient { get; init; }

        public bool RequirePkce { get; init; }

        public string ConsentType { get; init; } = OpenIddictConstants.ConsentTypes.Explicit;
    }
}
