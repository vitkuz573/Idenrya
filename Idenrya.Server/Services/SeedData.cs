using System.Security.Claims;
using Idenrya.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public static class SeedData
{
    private static readonly string[] ManagedProfileClaimTypes =
    [
        OpenIddictConstants.Claims.Name,
        OpenIddictConstants.Claims.GivenName,
        OpenIddictConstants.Claims.FamilyName,
        OpenIddictConstants.Claims.PreferredUsername,
        OpenIddictConstants.Claims.MiddleName,
        OpenIddictConstants.Claims.Nickname,
        OpenIddictConstants.Claims.Profile,
        OpenIddictConstants.Claims.Picture,
        OpenIddictConstants.Claims.Website,
        OpenIddictConstants.Claims.Gender,
        OpenIddictConstants.Claims.Birthdate,
        OpenIddictConstants.Claims.Zoneinfo,
        OpenIddictConstants.Claims.Locale,
        OpenIddictConstants.Claims.UpdatedAt
    ];

    public static async Task InitializeAsync(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<ConformanceOptions>>().Value;
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var appManager = services.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var user in options.GetSeedUsers())
        {
            await EnsureSeedUserAsync(userManager, user);
        }

        foreach (var client in options.GetSeedClients())
        {
            await EnsureSeedClientAsync(appManager, client);
        }
    }

    private static async Task EnsureSeedUserAsync(
        UserManager<ApplicationUser> userManager,
        ConformanceUserOptions userOptions)
    {
        if (string.IsNullOrWhiteSpace(userOptions.UserName))
        {
            throw new InvalidOperationException("Seed user username must be provided.");
        }

        if (string.IsNullOrWhiteSpace(userOptions.Password))
        {
            throw new InvalidOperationException($"Seed user '{userOptions.UserName}' password must be provided.");
        }

        var user = await userManager.FindByNameAsync(userOptions.UserName);
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = userOptions.UserName
            };

            ApplyUserProfile(user, userOptions);

            var createResult = await userManager.CreateAsync(user, userOptions.Password);
            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to create seed user '{userOptions.UserName}': {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
            }

            await EnsureManagedClaimsAsync(userManager, user, userOptions);
            return;
        }

        user.UserName = userOptions.UserName;
        ApplyUserProfile(user, userOptions);

        var updateResult = await userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to update seed user '{userOptions.UserName}': {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
        }

        if (!await userManager.CheckPasswordAsync(user, userOptions.Password))
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var reset = await userManager.ResetPasswordAsync(user, token, userOptions.Password);
            if (!reset.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to reset seed user '{userOptions.UserName}' password: {string.Join(", ", reset.Errors.Select(e => e.Description))}");
            }
        }

        await EnsureManagedClaimsAsync(userManager, user, userOptions);
    }

    private static async Task EnsureManagedClaimsAsync(
        UserManager<ApplicationUser> userManager,
        ApplicationUser user,
        ConformanceUserOptions userOptions)
    {
        var desiredClaims = BuildManagedClaims(userOptions);

        var managedClaimTypes = new HashSet<string>(ManagedProfileClaimTypes, StringComparer.Ordinal);
        foreach (var claimType in userOptions.Claims.Keys)
        {
            managedClaimTypes.Add(claimType);
        }

        var existingClaims = await userManager.GetClaimsAsync(user);
        var claimsToRemove = existingClaims
            .Where(claim => managedClaimTypes.Contains(claim.Type))
            .ToArray();

        if (claimsToRemove.Length > 0)
        {
            var removeResult = await userManager.RemoveClaimsAsync(user, claimsToRemove);
            if (!removeResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to remove managed claims for seed user '{userOptions.UserName}': {string.Join(", ", removeResult.Errors.Select(e => e.Description))}");
            }
        }

        var claimsToAdd = desiredClaims
            .Where(static pair => !string.IsNullOrWhiteSpace(pair.Value))
            .Select(pair => new Claim(pair.Key, pair.Value!))
            .ToArray();

        if (claimsToAdd.Length == 0)
        {
            return;
        }

        var addResult = await userManager.AddClaimsAsync(user, claimsToAdd);
        if (!addResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to add managed claims for seed user '{userOptions.UserName}': {string.Join(", ", addResult.Errors.Select(e => e.Description))}");
        }
    }

    private static Dictionary<string, string?> BuildManagedClaims(ConformanceUserOptions userOptions)
    {
        var claims = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Name] = $"{userOptions.GivenName} {userOptions.FamilyName}".Trim(),
            [OpenIddictConstants.Claims.GivenName] = userOptions.GivenName,
            [OpenIddictConstants.Claims.FamilyName] = userOptions.FamilyName,
            [OpenIddictConstants.Claims.PreferredUsername] = userOptions.UserName
        };

        foreach (var claim in userOptions.Claims)
        {
            claims[claim.Key] = claim.Value;
        }

        return claims;
    }

    private static void ApplyUserProfile(ApplicationUser user, ConformanceUserOptions options)
    {
        user.Email = options.Email;
        user.EmailConfirmed = options.EmailConfirmed;
        user.PhoneNumber = options.PhoneNumber;
        user.PhoneNumberConfirmed = options.PhoneNumberConfirmed;
        user.GivenName = options.GivenName;
        user.FamilyName = options.FamilyName;
        user.Address = options.Address;
    }

    private static async Task EnsureSeedClientAsync(
        IOpenIddictApplicationManager appManager,
        ConformanceClientOptions clientOptions)
    {
        if (string.IsNullOrWhiteSpace(clientOptions.ClientId))
        {
            throw new InvalidOperationException("Seed client id must be provided.");
        }

        if (clientOptions.RedirectUris.Count == 0)
        {
            throw new InvalidOperationException($"Seed client '{clientOptions.ClientId}' must have at least one redirect URI.");
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientOptions.ClientId,
            ClientSecret = clientOptions.ClientSecret,
            DisplayName = clientOptions.DisplayName,
            ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
            ClientType = string.IsNullOrWhiteSpace(clientOptions.ClientSecret)
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit
        };

        foreach (var redirectUri in clientOptions.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Revocation);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);

        var scopes = clientOptions.Scopes
            .Where(static scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (scopes.Count == 0)
        {
            scopes.Add(OpenIddictConstants.Scopes.OpenId);
        }

        foreach (var scope in scopes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        var existing = await appManager.FindByClientIdAsync(clientOptions.ClientId);
        if (existing is null)
        {
            await appManager.CreateAsync(descriptor);
            return;
        }

        await appManager.UpdateAsync(existing, descriptor);
    }
}
