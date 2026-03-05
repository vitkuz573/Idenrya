namespace Idenrya.Server.Services.OpenId;

public interface IAuthorizationErrorRedirectUriBuilder
{
    Task<string?> BuildAsync(HttpRequest request, string error, CancellationToken cancellationToken = default);
}
