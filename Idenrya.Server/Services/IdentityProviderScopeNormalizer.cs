using Idenrya.Server.Models;

namespace Idenrya.Server.Services;

public static class IdentityProviderScopeNormalizer
{
    public static string[] NormalizeSupportedScopes(IEnumerable<string> scopes)
    {
        var normalized = scopes
            .Where(static scope => !string.IsNullOrWhiteSpace(scope))
            .Select(static scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new InvalidOperationException("IdentityProvider:SupportedScopes must contain at least one scope.");
        }

        if (!normalized.Contains(OpenIdScopeNames.OpenId, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"IdentityProvider:SupportedScopes must include '{OpenIdScopeNames.OpenId}'.");
        }

        return normalized;
    }

    public static IReadOnlyList<string> NormalizeClientScopes(
        IEnumerable<string> scopes,
        IReadOnlyCollection<string> supportedScopes)
    {
        var normalized = scopes
            .Where(static scope => !string.IsNullOrWhiteSpace(scope))
            .Select(static scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (normalized.Count == 0)
        {
            normalized.Add(OpenIdScopeNames.OpenId);
        }

        var unsupportedScopes = normalized
            .Where(scope => !supportedScopes.Contains(scope, StringComparer.Ordinal))
            .ToArray();
        if (unsupportedScopes.Length > 0)
        {
            throw new ArgumentException(
                $"Unsupported scopes: {string.Join(", ", unsupportedScopes)}.",
                nameof(scopes));
        }

        return normalized;
    }
}
