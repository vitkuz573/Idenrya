using Idenrya.Server.Models.Admin;

namespace Idenrya.Server.Services;

public interface IIdentityProviderRoleService
{
    Task<IReadOnlyList<OpenIdRoleResponse>> ListAsync(CancellationToken cancellationToken = default);

    Task<OpenIdRoleResponse> CreateAsync(
        CreateOpenIdRoleRequest request,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(string roleName, CancellationToken cancellationToken = default);
}
