using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;

namespace Idenrya.Server.Services;

public interface IIdentityProviderUserService
{
    Task<IReadOnlyList<OpenIdUserResponse>> ListAsync(CancellationToken cancellationToken = default);

    Task<OpenIdUserResponse?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default);

    Task<OpenIdUserResponse> CreateAsync(
        CreateOpenIdUserRequest request,
        CancellationToken cancellationToken = default);

    Task<OpenIdUserResponse?> UpdateAsync(
        string userName,
        UpdateOpenIdUserRequest request,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string userName, CancellationToken cancellationToken = default);

    Task UpsertBootstrapUserAsync(
        IdentityProviderUserOptions options,
        CancellationToken cancellationToken = default);
}
