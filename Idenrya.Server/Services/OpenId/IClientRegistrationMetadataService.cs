namespace Idenrya.Server.Services.OpenId;

public interface IClientRegistrationMetadataService
{
    Task<string?> GetIdTokenSignedResponseAlgAsync(
        string? clientId,
        CancellationToken cancellationToken = default);

    Task<bool> RequiresUnsignedIdTokenAsync(
        string? clientId,
        CancellationToken cancellationToken = default);
}
