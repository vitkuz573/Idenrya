using Idenrya.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public static class SeedData
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<ConformanceOptions>>().Value;
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var appManager = services.GetRequiredService<IOpenIddictApplicationManager>();

        await EnsureConformanceUserAsync(userManager);
        await EnsureConformanceClientAsync(
            appManager,
            options.ClientId,
            options.ClientSecret,
            options.RedirectUri,
            "Idenrya static conformance client #1");

        await EnsureConformanceClientAsync(
            appManager,
            options.Client2Id,
            options.Client2Secret,
            options.RedirectUri2,
            "Idenrya static conformance client #2");
    }

    private static async Task EnsureConformanceUserAsync(UserManager<ApplicationUser> userManager)
    {
        var user = await userManager.FindByNameAsync("foo");
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = "foo",
                Email = "foo@idenrya.local",
                EmailConfirmed = true,
                PhoneNumber = "+1-555-0100",
                PhoneNumberConfirmed = true,
                GivenName = "Conformance",
                FamilyName = "User",
                Address = "123 Test Street, Test City"
            };

            var createResult = await userManager.CreateAsync(user, "bar");
            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to create conformance user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
            }

            return;
        }

        user.Email = "foo@idenrya.local";
        user.EmailConfirmed = true;
        user.PhoneNumber = "+1-555-0100";
        user.PhoneNumberConfirmed = true;
        user.GivenName = "Conformance";
        user.FamilyName = "User";
        user.Address = "123 Test Street, Test City";

        var updateResult = await userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to update conformance user: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
        }

        if (!await userManager.CheckPasswordAsync(user, "bar"))
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var reset = await userManager.ResetPasswordAsync(user, token, "bar");
            if (!reset.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to reset conformance user password: {string.Join(", ", reset.Errors.Select(e => e.Description))}");
            }
        }
    }

    private static async Task EnsureConformanceClientAsync(
        IOpenIddictApplicationManager appManager,
        string clientId,
        string clientSecret,
        string redirectUri,
        string displayName)
    {
        var existing = await appManager.FindByClientIdAsync(clientId);
        if (existing is not null)
        {
            await appManager.DeleteAsync(existing);
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = displayName,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit
        };

        descriptor.RedirectUris.Add(new Uri(redirectUri));

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Address);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Phone);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess);

        await appManager.CreateAsync(descriptor);
    }
}
