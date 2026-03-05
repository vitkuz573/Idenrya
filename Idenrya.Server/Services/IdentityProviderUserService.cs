using System.Security.Claims;
using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderUserService(
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager) : IIdentityProviderUserService
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

    public async Task<IReadOnlyList<OpenIdUserResponse>> ListAsync(CancellationToken cancellationToken = default)
    {
        var users = await userManager.Users
            .OrderBy(static user => user.UserName)
            .ToListAsync(cancellationToken);

        var result = new List<OpenIdUserResponse>(users.Count);
        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            result.Add(await BuildResponseAsync(user));
        }

        return result;
    }

    public async Task<OpenIdUserResponse?> FindByUserNameAsync(
        string userName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(userName))
        {
            return null;
        }

        var user = await userManager.FindByNameAsync(userName.Trim());
        return user is null ? null : await BuildResponseAsync(user);
    }

    public async Task<OpenIdUserResponse> CreateAsync(
        CreateOpenIdUserRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var normalized = NormalizeRequest(
            request.UserName,
            request.Password,
            request.Email,
            request.EmailConfirmed,
            request.PhoneNumber,
            request.PhoneNumberConfirmed,
            request.GivenName,
            request.FamilyName,
            request.Address,
            request.Roles,
            request.Claims,
            passwordRequired: true);

        var existing = await userManager.FindByNameAsync(normalized.UserName);
        if (existing is not null)
        {
            throw new InvalidOperationException($"User '{normalized.UserName}' already exists.");
        }

        var user = new ApplicationUser
        {
            UserName = normalized.UserName
        };

        ApplyUserProfile(user, normalized);

        var createResult = await userManager.CreateAsync(user, normalized.Password!);
        EnsureIdentityResultSucceeded(createResult, $"Failed to create user '{normalized.UserName}'");

        await EnsureManagedClaimsAsync(user, normalized);
        await SyncUserRolesAsync(user, normalized.Roles);

        return await BuildResponseAsync(user);
    }

    public async Task<OpenIdUserResponse?> UpdateAsync(
        string userName,
        UpdateOpenIdUserRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateUserName(userName);

        var existing = await userManager.FindByNameAsync(userName.Trim());
        if (existing is null)
        {
            return null;
        }

        var normalized = NormalizeRequest(
            existing.UserName ?? userName.Trim(),
            request.Password,
            request.Email,
            request.EmailConfirmed,
            request.PhoneNumber,
            request.PhoneNumberConfirmed,
            request.GivenName,
            request.FamilyName,
            request.Address,
            request.Roles,
            request.Claims,
            passwordRequired: false);

        ApplyUserProfile(existing, normalized);

        var updateResult = await userManager.UpdateAsync(existing);
        EnsureIdentityResultSucceeded(updateResult, $"Failed to update user '{normalized.UserName}'");

        await UpdatePasswordIfNeededAsync(existing, normalized.Password);
        await EnsureManagedClaimsAsync(existing, normalized);
        await SyncUserRolesAsync(existing, normalized.Roles);

        return await BuildResponseAsync(existing);
    }

    public async Task<bool> DeleteAsync(string userName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateUserName(userName);

        var existing = await userManager.FindByNameAsync(userName.Trim());
        if (existing is null)
        {
            return false;
        }

        var deleteResult = await userManager.DeleteAsync(existing);
        EnsureIdentityResultSucceeded(deleteResult, $"Failed to delete user '{existing.UserName}'");

        return true;
    }

    public async Task UpsertBootstrapUserAsync(
        IdentityProviderUserOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var normalized = NormalizeRequest(
            options.UserName,
            options.Password,
            options.Email,
            options.EmailConfirmed,
            options.PhoneNumber,
            options.PhoneNumberConfirmed,
            options.GivenName,
            options.FamilyName,
            options.Address,
            options.Roles,
            options.Claims,
            passwordRequired: true);

        var existing = await userManager.FindByNameAsync(normalized.UserName);
        if (existing is null)
        {
            var user = new ApplicationUser
            {
                UserName = normalized.UserName
            };

            ApplyUserProfile(user, normalized);

            var createResult = await userManager.CreateAsync(user, normalized.Password!);
            EnsureIdentityResultSucceeded(createResult, $"Failed to create seed user '{normalized.UserName}'");

            await EnsureManagedClaimsAsync(user, normalized);
            await SyncUserRolesAsync(user, normalized.Roles);
            return;
        }

        ApplyUserProfile(existing, normalized);

        var updateResult = await userManager.UpdateAsync(existing);
        EnsureIdentityResultSucceeded(updateResult, $"Failed to update seed user '{normalized.UserName}'");

        await UpdatePasswordIfNeededAsync(existing, normalized.Password);
        await EnsureManagedClaimsAsync(existing, normalized);
        await SyncUserRolesAsync(existing, normalized.Roles);
    }

    private async Task<OpenIdUserResponse> BuildResponseAsync(ApplicationUser user)
    {
        var roles = (await userManager.GetRolesAsync(user))
            .OrderBy(static role => role, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var claims = await userManager.GetClaimsAsync(user);
        var claimMap = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var claim in claims)
        {
            if (string.IsNullOrWhiteSpace(claim.Type) || string.IsNullOrWhiteSpace(claim.Value))
            {
                continue;
            }

            claimMap[claim.Type] = claim.Value;
        }

        return new OpenIdUserResponse
        {
            Id = user.Id,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber ?? string.Empty,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            GivenName = user.GivenName,
            FamilyName = user.FamilyName,
            Address = user.Address,
            Roles = roles,
            Claims = claimMap
        };
    }

    private static void ValidateUserName(string userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new ArgumentException("UserName must be provided.", nameof(userName));
        }
    }

    private static UserConfiguration NormalizeRequest(
        string userName,
        string? password,
        string? email,
        bool emailConfirmed,
        string? phoneNumber,
        bool phoneNumberConfirmed,
        string? givenName,
        string? familyName,
        string? address,
        IEnumerable<string> roles,
        IReadOnlyDictionary<string, string?> claims,
        bool passwordRequired)
    {
        ValidateUserName(userName);

        var normalizedUserName = userName.Trim();
        var normalizedPassword = string.IsNullOrWhiteSpace(password) ? null : password;

        if (passwordRequired && string.IsNullOrWhiteSpace(normalizedPassword))
        {
            throw new ArgumentException($"Password for user '{normalizedUserName}' must be provided.", nameof(password));
        }

        var normalizedRoles = roles
            .Where(static role => !string.IsNullOrWhiteSpace(role))
            .Select(static role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var normalizedClaims = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var claim in claims)
        {
            var claimType = claim.Key?.Trim();
            if (string.IsNullOrWhiteSpace(claimType))
            {
                continue;
            }

            normalizedClaims[claimType] = string.IsNullOrWhiteSpace(claim.Value) ? null : claim.Value.Trim();
        }

        return new UserConfiguration
        {
            UserName = normalizedUserName,
            Password = normalizedPassword,
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            EmailConfirmed = emailConfirmed,
            PhoneNumber = string.IsNullOrWhiteSpace(phoneNumber) ? null : phoneNumber.Trim(),
            PhoneNumberConfirmed = phoneNumberConfirmed,
            GivenName = (givenName ?? string.Empty).Trim(),
            FamilyName = (familyName ?? string.Empty).Trim(),
            Address = (address ?? string.Empty).Trim(),
            Roles = normalizedRoles,
            Claims = normalizedClaims
        };
    }

    private static void ApplyUserProfile(ApplicationUser user, UserConfiguration configuration)
    {
        user.Email = configuration.Email;
        user.EmailConfirmed = configuration.EmailConfirmed;
        user.PhoneNumber = configuration.PhoneNumber;
        user.PhoneNumberConfirmed = configuration.PhoneNumberConfirmed;
        user.GivenName = configuration.GivenName;
        user.FamilyName = configuration.FamilyName;
        user.Address = configuration.Address;
    }

    private async Task UpdatePasswordIfNeededAsync(ApplicationUser user, string? newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword) || await userManager.CheckPasswordAsync(user, newPassword))
        {
            return;
        }

        var resetToken = await userManager.GeneratePasswordResetTokenAsync(user);
        var resetResult = await userManager.ResetPasswordAsync(user, resetToken, newPassword);
        EnsureIdentityResultSucceeded(resetResult, $"Failed to update password for user '{user.UserName}'");
    }

    private async Task EnsureManagedClaimsAsync(ApplicationUser user, UserConfiguration configuration)
    {
        var desiredClaims = BuildManagedClaims(configuration);

        var managedClaimTypes = new HashSet<string>(ManagedProfileClaimTypes, StringComparer.Ordinal);
        foreach (var claimType in configuration.Claims.Keys)
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
            EnsureIdentityResultSucceeded(removeResult, $"Failed to remove managed claims for user '{user.UserName}'");
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
        EnsureIdentityResultSucceeded(addResult, $"Failed to add managed claims for user '{user.UserName}'");
    }

    private async Task SyncUserRolesAsync(ApplicationUser user, IReadOnlyList<string> desiredRoles)
    {
        foreach (var role in desiredRoles)
        {
            if (await roleManager.RoleExistsAsync(role))
            {
                continue;
            }

            var createRole = await roleManager.CreateAsync(new IdentityRole(role));
            EnsureIdentityResultSucceeded(createRole, $"Failed to create role '{role}' for user '{user.UserName}'");
        }

        var existingRoles = await userManager.GetRolesAsync(user);

        var rolesToRemove = existingRoles
            .Where(role => !desiredRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (rolesToRemove.Length > 0)
        {
            var removeRoles = await userManager.RemoveFromRolesAsync(user, rolesToRemove);
            EnsureIdentityResultSucceeded(removeRoles, $"Failed to remove roles for user '{user.UserName}'");
        }

        var rolesToAdd = desiredRoles
            .Where(role => !existingRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (rolesToAdd.Length == 0)
        {
            return;
        }

        var addRoles = await userManager.AddToRolesAsync(user, rolesToAdd);
        EnsureIdentityResultSucceeded(addRoles, $"Failed to assign roles for user '{user.UserName}'");
    }

    private static Dictionary<string, string?> BuildManagedClaims(UserConfiguration configuration)
    {
        var claims = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Name] = $"{configuration.GivenName} {configuration.FamilyName}".Trim(),
            [OpenIddictConstants.Claims.GivenName] = configuration.GivenName,
            [OpenIddictConstants.Claims.FamilyName] = configuration.FamilyName,
            [OpenIddictConstants.Claims.PreferredUsername] = configuration.UserName
        };

        foreach (var claim in configuration.Claims)
        {
            claims[claim.Key] = claim.Value;
        }

        return claims;
    }

    private static void EnsureIdentityResultSucceeded(IdentityResult result, string messagePrefix)
    {
        if (result.Succeeded)
        {
            return;
        }

        throw new InvalidOperationException(
            $"{messagePrefix}: {string.Join(", ", result.Errors.Select(static error => error.Description))}");
    }

    private sealed class UserConfiguration
    {
        public string UserName { get; init; } = string.Empty;

        public string? Password { get; init; }

        public string? Email { get; init; }

        public bool EmailConfirmed { get; init; }

        public string? PhoneNumber { get; init; }

        public bool PhoneNumberConfirmed { get; init; }

        public string GivenName { get; init; } = string.Empty;

        public string FamilyName { get; init; } = string.Empty;

        public string Address { get; init; } = string.Empty;

        public List<string> Roles { get; init; } = [];

        public Dictionary<string, string?> Claims { get; init; } = new(StringComparer.Ordinal);
    }
}
