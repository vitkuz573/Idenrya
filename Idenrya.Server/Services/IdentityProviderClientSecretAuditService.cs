using Idenrya.Server.Data;
using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Microsoft.EntityFrameworkCore;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderClientSecretAuditService(
    ApplicationDbContext dbContext) : IIdentityProviderClientSecretAuditService
{
    public async Task RecordAsync(
        string clientId,
        DateTimeOffset rotatedAtUtc,
        string source,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("ClientId must be provided.", nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(source))
        {
            throw new ArgumentException("Rotation source must be provided.", nameof(source));
        }

        dbContext.ClientSecretRotationAudits.Add(new ClientSecretRotationAuditEntry
        {
            ClientId = clientId.Trim(),
            RotatedAtUtc = rotatedAtUtc,
            Source = source.Trim()
        });

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<OpenIdClientSecretRotationAuditResponse>> ListAsync(
        string clientId,
        int take,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("ClientId must be provided.", nameof(clientId));
        }

        var normalizedClientId = clientId.Trim();
        var normalizedTake = Math.Clamp(take, 1, 200);

        return await dbContext.ClientSecretRotationAudits
            .AsNoTracking()
            .Where(entry => entry.ClientId == normalizedClientId)
            .OrderByDescending(static entry => entry.RotatedAtUtc)
            .ThenByDescending(static entry => entry.Id)
            .Take(normalizedTake)
            .Select(entry => new OpenIdClientSecretRotationAuditResponse
            {
                ClientId = entry.ClientId,
                RotatedAtUtc = entry.RotatedAtUtc,
                Source = entry.Source
            })
            .ToArrayAsync(cancellationToken);
    }
}
