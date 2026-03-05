using Idenrya.Server.Models;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Idenrya.Server.Services.OpenId;

public sealed class UnsignedIdTokenGenerationHandler(
    IClientRegistrationMetadataService clientRegistrationMetadataService,
    IOptions<IdentityProviderOptions> identityProviderOptions)
    : IOpenIddictServerHandler<OpenIddictServerEvents.GenerateTokenContext>
{
    public const string UnsignedIdTokenRequiredTransactionProperty = "idenrya.unsigned_id_token_required";

    public async ValueTask HandleAsync(OpenIddictServerEvents.GenerateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!identityProviderOptions.Value.DynamicClientRegistration.AllowUnsignedIdTokens ||
            !IsIdentityToken(context.TokenType))
        {
            return;
        }

        var clientId = context.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            clientId = context.Principal?.GetPresenters().FirstOrDefault();
        }

        if (!await clientRegistrationMetadataService.RequiresUnsignedIdTokenAsync(clientId, context.CancellationToken))
        {
            return;
        }

        context.Transaction.SetProperty(UnsignedIdTokenRequiredTransactionProperty, "1");

        if (string.IsNullOrWhiteSpace(context.Token))
        {
            context.SigningCredentials = null;
            context.SecurityTokenDescriptor.SigningCredentials = null;
            return;
        }

        var segments = context.Token.Split('.');
        if (segments.Length != 3 || string.IsNullOrWhiteSpace(segments[1]))
        {
            return;
        }

        context.Token = UnsignedIdTokenFormatter.RewriteTokenWithNoneAlgorithm(segments[1]);
    }

    private static bool IsIdentityToken(string? tokenType)
    {
        return string.Equals(tokenType, OpenIddictConstants.TokenTypeIdentifiers.IdentityToken, StringComparison.Ordinal) ||
               string.Equals(tokenType, OpenIddictConstants.Parameters.IdToken, StringComparison.Ordinal) ||
               string.Equals(tokenType, OpenIddictConstants.ResponseTypes.IdToken, StringComparison.Ordinal);
    }
}
