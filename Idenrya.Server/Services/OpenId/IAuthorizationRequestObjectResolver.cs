namespace Idenrya.Server.Services.OpenId;

public interface IAuthorizationRequestObjectResolver
{
    Task<string?> ResolveRedirectUriAsync(HttpRequest request, CancellationToken cancellationToken = default);
}
