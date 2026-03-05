using System.Text.Json;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services.OpenId;

public sealed class ClientRegistrationMetadataService(
    IOpenIddictApplicationManager applicationManager)
    : IClientRegistrationMetadataService
{
    public async Task<string?> GetIdTokenSignedResponseAlgAsync(
        string? clientId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var application = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null)
        {
            return null;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        if (!descriptor.Properties.TryGetValue(
                OpenIdClientRegistrationPropertyNames.IdTokenSignedResponseAlg,
                out var propertyValue) ||
            propertyValue.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var value = propertyValue.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    public async Task<bool> RequiresUnsignedIdTokenAsync(
        string? clientId,
        CancellationToken cancellationToken = default)
    {
        var value = await GetIdTokenSignedResponseAlgAsync(clientId, cancellationToken);
        return string.Equals(value, "none", StringComparison.Ordinal);
    }
}
