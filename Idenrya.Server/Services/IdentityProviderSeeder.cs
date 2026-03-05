using Idenrya.Server.Models;
using Microsoft.Extensions.Options;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderSeeder(
    IOptions<IdentityProviderOptions> options,
    IIdentityProviderScopeService scopeService,
    IIdentityProviderUserService userService,
    IIdentityProviderClientService clientService,
    ILogger<IdentityProviderSeeder> logger) : IIdentityProviderSeeder
{
    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        var settings = options.Value;
        await scopeService.UpsertSupportedScopesAsync(settings.SupportedScopes, cancellationToken);

        var bootstrap = settings.Bootstrap;
        if (!bootstrap.Enabled)
        {
            logger.LogInformation("Identity bootstrap is disabled.");
            return;
        }

        foreach (var user in bootstrap.Users.Where(static user => !string.IsNullOrWhiteSpace(user.UserName)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await userService.UpsertBootstrapUserAsync(user, cancellationToken);
        }

        foreach (var client in bootstrap.Clients.Where(static client => !string.IsNullOrWhiteSpace(client.ClientId)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await clientService.UpsertBootstrapClientAsync(client, cancellationToken);
        }
    }
}
