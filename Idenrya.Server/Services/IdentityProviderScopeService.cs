using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderScopeService(
    IOpenIddictScopeManager scopeManager,
    IOpenIddictApplicationManager applicationManager) : IIdentityProviderScopeService
{
    public async Task<IReadOnlyList<OpenIdScopeResponse>> ListAsync(CancellationToken cancellationToken = default)
    {
        var scopes = new List<OpenIdScopeResponse>();

        await foreach (var scope in scopeManager.ListAsync(null, null, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            scopes.Add(await BuildResponseAsync(scope, cancellationToken));
        }

        return scopes
            .OrderBy(static scope => scope.Name, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<OpenIdScopeResponse?> FindByNameAsync(
        string scopeName,
        CancellationToken cancellationToken = default)
    {
        var normalizedScopeName = NormalizeScopeName(scopeName);
        var scope = await scopeManager.FindByNameAsync(normalizedScopeName, cancellationToken);
        return scope is null ? null : await BuildResponseAsync(scope, cancellationToken);
    }

    public async Task<OpenIdScopeResponse> CreateAsync(
        CreateOpenIdScopeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = NormalizeScopeConfiguration(request.Name, request.DisplayName, request.Resources);

        var existing = await scopeManager.FindByNameAsync(normalized.Name, cancellationToken);
        if (existing is not null)
        {
            throw new InvalidOperationException($"Scope '{normalized.Name}' already exists.");
        }

        var descriptor = BuildDescriptor(normalized.Name, normalized.DisplayName, normalized.Resources);
        await scopeManager.CreateAsync(descriptor, cancellationToken);

        var created = await scopeManager.FindByNameAsync(normalized.Name, cancellationToken)
                      ?? throw new InvalidOperationException(
                          $"Scope '{normalized.Name}' was created but cannot be retrieved.");

        return await BuildResponseAsync(created, cancellationToken);
    }

    public async Task<bool> DeleteAsync(string scopeName, CancellationToken cancellationToken = default)
    {
        var normalizedScopeName = NormalizeScopeName(scopeName);
        if (string.Equals(normalizedScopeName, OpenIdScopeNames.OpenId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Scope 'openid' is mandatory and cannot be deleted.");
        }

        var scope = await scopeManager.FindByNameAsync(normalizedScopeName, cancellationToken);
        if (scope is null)
        {
            return false;
        }

        await EnsureScopeNotAssignedToAnyClientAsync(normalizedScopeName, cancellationToken);
        await scopeManager.DeleteAsync(scope, cancellationToken);
        return true;
    }

    public async Task<IReadOnlyList<string>> GetSupportedScopesAsync(CancellationToken cancellationToken = default)
    {
        var scopes = await ListAsync(cancellationToken);
        return scopes
            .Select(static scope => scope.Name)
            .ToArray();
    }

    public async Task<IReadOnlyList<string>> NormalizeClientScopesAsync(
        IEnumerable<string> scopes,
        CancellationToken cancellationToken = default)
    {
        var supportedScopes = await GetSupportedScopesAsync(cancellationToken);
        return IdentityProviderScopeNormalizer.NormalizeClientScopes(scopes, supportedScopes);
    }

    public async Task UpsertSupportedScopesAsync(
        IEnumerable<string> scopes,
        CancellationToken cancellationToken = default)
    {
        var normalizedScopes = IdentityProviderScopeNormalizer.NormalizeSupportedScopes(scopes);
        foreach (var scopeName in normalizedScopes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var existing = await scopeManager.FindByNameAsync(scopeName, cancellationToken);
            if (existing is not null)
            {
                continue;
            }

            var descriptor = BuildDescriptor(scopeName, scopeName, []);

            await scopeManager.CreateAsync(descriptor, cancellationToken);
        }
    }

    private async Task EnsureScopeNotAssignedToAnyClientAsync(
        string scopeName,
        CancellationToken cancellationToken)
    {
        var requiredPermission = OpenIddictConstants.Permissions.Prefixes.Scope + scopeName;

        await foreach (var application in applicationManager.ListAsync(null, null, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var descriptor = new OpenIddictApplicationDescriptor();
            await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

            if (!descriptor.Permissions.Contains(requiredPermission, StringComparer.Ordinal))
            {
                continue;
            }

            var clientId = string.IsNullOrWhiteSpace(descriptor.ClientId)
                ? "unknown"
                : descriptor.ClientId;

            throw new InvalidOperationException(
                $"Scope '{scopeName}' is assigned to client '{clientId}'. Remove it from clients first.");
        }
    }

    private async Task<OpenIdScopeResponse> BuildResponseAsync(
        object scope,
        CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictScopeDescriptor();
        await scopeManager.PopulateAsync(descriptor, scope, cancellationToken);

        var scopeName = descriptor.Name ?? string.Empty;
        var displayName = string.IsNullOrWhiteSpace(descriptor.DisplayName)
            ? scopeName
            : descriptor.DisplayName;

        return new OpenIdScopeResponse
        {
            Name = scopeName,
            DisplayName = displayName,
            Resources = descriptor.Resources
                .OrderBy(static resource => resource, StringComparer.Ordinal)
                .ToList()
        };
    }

    private static OpenIddictScopeDescriptor BuildDescriptor(
        string name,
        string displayName,
        IReadOnlyList<string> resources)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = name,
            DisplayName = displayName
        };

        foreach (var resource in resources)
        {
            descriptor.Resources.Add(resource);
        }

        return descriptor;
    }

    private static ScopeConfiguration NormalizeScopeConfiguration(
        string scopeName,
        string? displayName,
        IEnumerable<string> resources)
    {
        var normalizedScopeName = NormalizeScopeName(scopeName);
        var normalizedDisplayName = string.IsNullOrWhiteSpace(displayName)
            ? normalizedScopeName
            : displayName.Trim();

        var normalizedResources = (resources ?? [])
            .Where(static resource => !string.IsNullOrWhiteSpace(resource))
            .Select(static resource => resource.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static resource => resource, StringComparer.Ordinal)
            .ToList();

        return new ScopeConfiguration
        {
            Name = normalizedScopeName,
            DisplayName = normalizedDisplayName,
            Resources = normalizedResources
        };
    }

    private static string NormalizeScopeName(string scopeName)
    {
        if (string.IsNullOrWhiteSpace(scopeName))
        {
            throw new ArgumentException("Scope name must be provided.", nameof(scopeName));
        }

        var normalized = scopeName.Trim();
        if (normalized.Length > 200)
        {
            throw new ArgumentException("Scope name is too long (max 200 characters).", nameof(scopeName));
        }

        if (normalized.Contains(' ', StringComparison.Ordinal))
        {
            throw new ArgumentException("Scope name cannot contain spaces.", nameof(scopeName));
        }

        return normalized;
    }

    private sealed class ScopeConfiguration
    {
        public string Name { get; init; } = string.Empty;

        public string DisplayName { get; init; } = string.Empty;

        public List<string> Resources { get; init; } = [];
    }
}
