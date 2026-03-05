namespace Idenrya.Server.Services;

public interface IIdentityProviderScopeService
{
    IReadOnlyList<string> GetSupportedScopes();

    IReadOnlyList<string> NormalizeClientScopes(IEnumerable<string> scopes);
}
