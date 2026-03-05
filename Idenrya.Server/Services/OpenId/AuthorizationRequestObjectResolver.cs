using Idenrya.Server.Options;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services.OpenId;

public sealed class AuthorizationRequestObjectResolver(
    IHttpRequestParameterReader parameterReader,
    IRequestObjectParser requestObjectParser,
    IRequestObjectByReferenceResolver requestObjectByReferenceResolver,
    IAuthorizationErrorRedirectUriBuilder errorRedirectUriBuilder,
    IAuthorizationRequestParameterMerger parameterMerger,
    IOptions<OpenIdProviderCompatibilityOptions> compatibilityOptions) : IAuthorizationRequestObjectResolver
{
    public async Task<string?> ResolveRedirectUriAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var requestObject = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.Request,
            cancellationToken);
        var requestUri = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.RequestUri,
            cancellationToken);

        if (string.IsNullOrWhiteSpace(requestObject) && string.IsNullOrWhiteSpace(requestUri))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(requestObject) && !string.IsNullOrWhiteSpace(requestUri))
        {
            return await errorRedirectUriBuilder.BuildAsync(
                request,
                OpenIddictConstants.Errors.InvalidRequest,
                cancellationToken);
        }

        if (!string.IsNullOrWhiteSpace(requestUri) && compatibilityOptions.Value.RejectRequestUriParameter)
        {
            return await errorRedirectUriBuilder.BuildAsync(
                request,
                OpenIddictConstants.Errors.RequestUriNotSupported,
                cancellationToken);
        }

        if (!string.IsNullOrWhiteSpace(requestUri))
        {
            var resolvedByReference = await requestObjectByReferenceResolver.ResolveAsync(
                request,
                requestUri,
                cancellationToken);
            if (!resolvedByReference.IsSuccess || resolvedByReference.Parameters is null)
            {
                return await errorRedirectUriBuilder.BuildAsync(
                    request,
                    resolvedByReference.Error ?? OpenIddictConstants.Errors.InvalidRequestUri,
                    cancellationToken);
            }

            var mergedByReference = await parameterMerger.MergeAsync(request, resolvedByReference.Parameters, cancellationToken);
            return QueryHelpers.AddQueryString($"{request.PathBase}{request.Path}", mergedByReference);
        }

        if (string.IsNullOrWhiteSpace(requestObject))
        {
            return null;
        }

        if (!requestObjectParser.TryParseUnsigned(requestObject, out var requestParameters))
        {
            return await errorRedirectUriBuilder.BuildAsync(
                request,
                OpenIddictConstants.Errors.InvalidRequestObject,
                cancellationToken);
        }

        var mergedParameters = await parameterMerger.MergeAsync(request, requestParameters, cancellationToken);
        return QueryHelpers.AddQueryString($"{request.PathBase}{request.Path}", mergedParameters);
    }
}
