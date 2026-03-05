using Idenrya.Server.Models;

namespace Idenrya.Server.Services;

public interface IOpenIdDynamicClientRegistrationService
{
    Task<OpenIdDynamicClientRegistrationResponse> RegisterAsync(
        OpenIdDynamicClientRegistrationRequest request,
        Uri registrationEndpointUri,
        string? initialAccessToken,
        CancellationToken cancellationToken = default);

    Task<OpenIdDynamicClientRegistrationResponse?> GetAsync(
        string clientId,
        Uri registrationEndpointUri,
        string? registrationAccessToken,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(
        string clientId,
        string? registrationAccessToken,
        CancellationToken cancellationToken = default);
}
