using System.Security.Claims;
using Idenrya.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderSeeder(
    IOptions<IdentityProviderOptions> options,
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IIdentityProviderClientService clientService,
    ILogger<IdentityProviderSeeder> logger) : IIdentityProviderSeeder
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

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        var bootstrap = options.Value.Bootstrap;
        if (!bootstrap.Enabled)
        {
            logger.LogInformation("Identity bootstrap is disabled.");
            return;
        }

        foreach (var user in bootstrap.Users.Where(static user => !string.IsNullOrWhiteSpace(user.UserName)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await EnsureSeedUserAsync(user);
        }

        foreach (var client in bootstrap.Clients.Where(static client => !string.IsNullOrWhiteSpace(client.ClientId)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await clientService.UpsertBootstrapClientAsync(client, cancellationToken);
        }
    }

    private async Task EnsureSeedUserAsync(IdentityProviderUserOptions userOptions)
    {
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

            await EnsureManagedClaimsAsync(user, userOptions);
            await EnsureUserRolesAsync(user, userOptions.Roles);
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

        await EnsureManagedClaimsAsync(user, userOptions);
        await EnsureUserRolesAsync(user, userOptions.Roles);
    }

    private async Task EnsureManagedClaimsAsync(
        ApplicationUser user,
        IdentityProviderUserOptions userOptions)
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

    private static Dictionary<string, string?> BuildManagedClaims(IdentityProviderUserOptions userOptions)
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

    private static void ApplyUserProfile(ApplicationUser user, IdentityProviderUserOptions options)
    {
        user.Email = options.Email;
        user.EmailConfirmed = options.EmailConfirmed;
        user.PhoneNumber = options.PhoneNumber;
        user.PhoneNumberConfirmed = options.PhoneNumberConfirmed;
        user.GivenName = options.GivenName;
        user.FamilyName = options.FamilyName;
        user.Address = options.Address;
    }

    private async Task EnsureUserRolesAsync(ApplicationUser user, IEnumerable<string> roles)
    {
        var normalizedRoles = roles
            .Where(static role => !string.IsNullOrWhiteSpace(role))
            .Select(static role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalizedRoles.Length == 0)
        {
            return;
        }

        foreach (var role in normalizedRoles)
        {
            if (await roleManager.RoleExistsAsync(role))
            {
                continue;
            }

            var createRole = await roleManager.CreateAsync(new IdentityRole(role));
            if (!createRole.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to create role '{role}' for seed user '{user.UserName}': " +
                    string.Join(", ", createRole.Errors.Select(error => error.Description)));
            }
        }

        var existingRoles = await userManager.GetRolesAsync(user);
        var missingRoles = normalizedRoles
            .Where(role => !existingRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (missingRoles.Length == 0)
        {
            return;
        }

        var addRoles = await userManager.AddToRolesAsync(user, missingRoles);
        if (!addRoles.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to assign roles to seed user '{user.UserName}': " +
                string.Join(", ", addRoles.Errors.Select(error => error.Description)));
        }
    }
}
