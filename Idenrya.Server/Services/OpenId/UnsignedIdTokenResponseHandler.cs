using System.Text;
using Idenrya.Server.Models;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Idenrya.Server.Services.OpenId;

public sealed class UnsignedIdTokenResponseHandler(
    IClientRegistrationMetadataService clientRegistrationMetadataService,
    IOptions<IdentityProviderOptions> identityProviderOptions)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyTokenResponseContext>
{
    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!identityProviderOptions.Value.DynamicClientRegistration.AllowUnsignedIdTokens)
        {
            return;
        }

        var idToken = context.Response?.IdToken;
        if (string.IsNullOrWhiteSpace(idToken))
        {
            return;
        }

        var marker = context.Transaction.GetProperty<string>(
            UnsignedIdTokenGenerationHandler.UnsignedIdTokenRequiredTransactionProperty);
        var requiresUnsignedIdToken = string.Equals(marker, "1", StringComparison.Ordinal);

        if (!requiresUnsignedIdToken)
        {
            var clientId = context.Request?.ClientId;
            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = TryExtractClientIdFromBasicAuthenticationHeader(context);
            }

            requiresUnsignedIdToken = await clientRegistrationMetadataService
                .RequiresUnsignedIdTokenAsync(clientId, context.CancellationToken);
            if (!requiresUnsignedIdToken)
            {
                return;
            }
        }

        var segments = idToken.Split('.');
        if (segments.Length != 3 || string.IsNullOrWhiteSpace(segments[1]))
        {
            return;
        }

        context.Response!.IdToken = UnsignedIdTokenFormatter.RewriteTokenWithNoneAlgorithm(segments[1]);
        context.Response[OpenIddictConstants.Parameters.IdToken] = context.Response.IdToken;
    }

    private static string? TryExtractClientIdFromBasicAuthenticationHeader(
        OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        var request = context.Transaction.GetHttpRequest();
        if (request is null ||
            !request.Headers.TryGetValue("Authorization", out var authorizationHeader))
        {
            return null;
        }

        var header = authorizationHeader.ToString();
        const string prefix = "Basic ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var encodedCredentials = header[prefix.Length..].Trim();
        if (string.IsNullOrWhiteSpace(encodedCredentials))
        {
            return null;
        }

        try
        {
            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            var separatorIndex = credentials.IndexOf(':');
            if (separatorIndex <= 0)
            {
                return null;
            }

            var clientId = credentials[..separatorIndex];
            return string.IsNullOrWhiteSpace(clientId) ? null : clientId;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
