using Idenrya.Server.Models;
using Idenrya.Server.Models.Admin;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderRoleService(
    RoleManager<IdentityRole> roleManager,
    UserManager<ApplicationUser> userManager) : IIdentityProviderRoleService
{
    public async Task<IReadOnlyList<OpenIdRoleResponse>> ListAsync(CancellationToken cancellationToken = default)
    {
        var roles = await roleManager.Roles
            .OrderBy(static role => role.Name)
            .ToListAsync(cancellationToken);

        return roles
            .Select(static role => new OpenIdRoleResponse
            {
                Id = role.Id,
                Name = role.Name ?? string.Empty
            })
            .ToArray();
    }

    public async Task<OpenIdRoleResponse> CreateAsync(
        CreateOpenIdRoleRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var roleName = NormalizeRoleName(request.Name);

        var existing = await roleManager.FindByNameAsync(roleName);
        if (existing is not null)
        {
            throw new InvalidOperationException($"Role '{roleName}' already exists.");
        }

        var role = new IdentityRole(roleName);
        var createResult = await roleManager.CreateAsync(role);
        EnsureIdentityResultSucceeded(createResult, $"Failed to create role '{roleName}'");

        return new OpenIdRoleResponse
        {
            Id = role.Id,
            Name = role.Name ?? roleName
        };
    }

    public async Task<bool> DeleteAsync(string roleName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedRoleName = NormalizeRoleName(roleName);

        var role = await roleManager.FindByNameAsync(normalizedRoleName);
        if (role is null)
        {
            return false;
        }

        var roleDisplayName = role.Name ?? normalizedRoleName;
        var usersInRole = await userManager.GetUsersInRoleAsync(roleDisplayName);
        foreach (var user in usersInRole)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var removeResult = await userManager.RemoveFromRoleAsync(user, roleDisplayName);
            EnsureIdentityResultSucceeded(
                removeResult,
                $"Failed to remove role '{roleDisplayName}' from user '{user.UserName}'");
        }

        var deleteResult = await roleManager.DeleteAsync(role);
        EnsureIdentityResultSucceeded(deleteResult, $"Failed to delete role '{roleDisplayName}'");

        return true;
    }

    private static string NormalizeRoleName(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            throw new ArgumentException("Role name must be provided.", nameof(roleName));
        }

        return roleName.Trim();
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
}
