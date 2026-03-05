using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderScopeService(
    IOpenIddictScopeManager scopeManager) : IIdentityProviderScopeService
{
    public async Task<IReadOnlyList<string>> GetSupportedScopesAsync(CancellationToken cancellationToken = default)
    {
        var scopeNames = new HashSet<string>(StringComparer.Ordinal);

        await foreach (var scope in scopeManager.ListAsync(null, null, cancellationToken))
        {
            var name = await scopeManager.GetNameAsync(scope, cancellationToken);
            if (!string.IsNullOrWhiteSpace(name))
            {
                scopeNames.Add(name);
            }
        }

        return scopeNames
            .OrderBy(static scope => scope, StringComparer.Ordinal)
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

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = scopeName,
                DisplayName = scopeName
            };

            await scopeManager.CreateAsync(descriptor, cancellationToken);
        }
    }
}
