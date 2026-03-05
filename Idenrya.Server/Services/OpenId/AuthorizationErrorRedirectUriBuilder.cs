using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services.OpenId;

public sealed class AuthorizationErrorRedirectUriBuilder(
    IHttpRequestParameterReader parameterReader,
    IOpenIddictApplicationManager applicationManager) : IAuthorizationErrorRedirectUriBuilder
{
    public async Task<string?> BuildAsync(HttpRequest request, string error, CancellationToken cancellationToken = default)
    {
        var clientId = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.ClientId,
            cancellationToken);
        var redirectUri = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.RedirectUri,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
        {
            return null;
        }

        var application = await applicationManager.FindByClientIdAsync(clientId);
        if (application is null)
        {
            return null;
        }

        var registeredRedirectUris = await applicationManager.GetRedirectUrisAsync(application);
        if (!registeredRedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return null;
        }

        var responseParameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Parameters.Error] = error
        };

        var state = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.State,
            cancellationToken);
        if (!string.IsNullOrWhiteSpace(state))
        {
            responseParameters[OpenIddictConstants.Parameters.State] = state;
        }

        return QueryHelpers.AddQueryString(redirectUri, responseParameters);
    }
}
