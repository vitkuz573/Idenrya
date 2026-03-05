using Idenrya.Server.Options;
using Idenrya.Server.Services.OpenId;
using Microsoft.Extensions.Options;

namespace Idenrya.Server.Middleware;

public sealed class AuthorizationRequestObjectMiddleware(RequestDelegate next)
{
    private const string AuthorizationEndpointPath = "/connect/authorize";

    public async Task InvokeAsync(
        HttpContext context,
        IAuthorizationRequestObjectResolver resolver,
        IOptions<OpenIdProviderCompatibilityOptions> options)
    {
        if (!options.Value.EnableRequestObjectParameterSupport ||
            !context.Request.Path.Equals(AuthorizationEndpointPath, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        var redirectUri = await resolver.ResolveRedirectUriAsync(context.Request, context.RequestAborted);
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            context.Response.Redirect(redirectUri);
            return;
        }

        await next(context);
    }
}
