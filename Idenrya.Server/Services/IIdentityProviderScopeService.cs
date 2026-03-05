using Idenrya.Server.Models.Admin;

namespace Idenrya.Server.Services;

public interface IIdentityProviderScopeService
{
    Task<IReadOnlyList<OpenIdScopeResponse>> ListAsync(CancellationToken cancellationToken = default);

    Task<OpenIdScopeResponse?> FindByNameAsync(string scopeName, CancellationToken cancellationToken = default);

    Task<OpenIdScopeResponse> CreateAsync(
        CreateOpenIdScopeRequest request,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string scopeName, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetSupportedScopesAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> NormalizeClientScopesAsync(
        IEnumerable<string> scopes,
        CancellationToken cancellationToken = default);

    Task UpsertSupportedScopesAsync(IEnumerable<string> scopes, CancellationToken cancellationToken = default);
}
