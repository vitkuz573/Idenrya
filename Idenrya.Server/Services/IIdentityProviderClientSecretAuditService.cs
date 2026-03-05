using Idenrya.Server.Models.Admin;

namespace Idenrya.Server.Services;

public interface IIdentityProviderClientSecretAuditService
{
    Task RecordAsync(
        string clientId,
        DateTimeOffset rotatedAtUtc,
        string source,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<OpenIdClientSecretRotationAuditResponse>> ListAsync(
        string clientId,
        int take,
        CancellationToken cancellationToken = default);
}
