using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;

namespace Idenrya.Server.Services;

public interface IIdentityProviderClientService
{
    Task<IReadOnlyList<OpenIdClientResponse>> ListAsync(CancellationToken cancellationToken = default);

    Task<OpenIdClientResponse?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);

    Task<OpenIdClientResponse> CreateAsync(
        CreateOpenIdClientRequest request,
        CancellationToken cancellationToken = default);

    Task<OpenIdClientResponse?> UpdateAsync(
        string clientId,
        UpdateOpenIdClientRequest request,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string clientId, CancellationToken cancellationToken = default);

    Task UpsertBootstrapClientAsync(
        IdentityProviderClientOptions options,
        CancellationToken cancellationToken = default);
}
