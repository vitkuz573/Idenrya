namespace Idenrya.Server.Services;

public interface IIdentityProviderScopeService
{
    Task<IReadOnlyList<string>> GetSupportedScopesAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> NormalizeClientScopesAsync(
        IEnumerable<string> scopes,
        CancellationToken cancellationToken = default);

    Task UpsertSupportedScopesAsync(IEnumerable<string> scopes, CancellationToken cancellationToken = default);
}
