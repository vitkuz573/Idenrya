using Idenrya.Server.Models;
using Microsoft.Extensions.Options;

namespace Idenrya.Server.Services;

public sealed class IdentityProviderScopeService(
    IOptions<IdentityProviderOptions> options) : IIdentityProviderScopeService
{
    private readonly string[] supportedScopes =
        IdentityProviderScopeNormalizer.NormalizeSupportedScopes(options.Value.SupportedScopes);

    public IReadOnlyList<string> GetSupportedScopes() => supportedScopes;

    public IReadOnlyList<string> NormalizeClientScopes(IEnumerable<string> scopes)
    {
        return IdentityProviderScopeNormalizer.NormalizeClientScopes(scopes, supportedScopes);
    }
}
