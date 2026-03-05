namespace Idenrya.Server.Models;

public sealed class ClientSecretRotationAuditEntry
{
    public long Id { get; set; }

    public string ClientId { get; set; } = string.Empty;

    public DateTimeOffset RotatedAtUtc { get; set; }

    public string Source { get; set; } = string.Empty;
}
