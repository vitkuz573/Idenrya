using System.Text.Json;
using Idenrya.Server.Options;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Services.OpenId;

public sealed class RequestObjectByReferenceResolver(
    IHttpRequestParameterReader parameterReader,
    IOpenIddictApplicationManager applicationManager,
    IRequestObjectParser requestObjectParser,
    IHttpClientFactory httpClientFactory,
    IOptions<OpenIdProviderCompatibilityOptions> compatibilityOptions)
    : IRequestObjectByReferenceResolver
{
    public async Task<RequestObjectByReferenceResolutionResult> ResolveAsync(
        HttpRequest request,
        string requestUri,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(requestUri))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequestUri);
        }

        if (!Uri.TryCreate(requestUri, UriKind.Absolute, out var parsedRequestUri) ||
            !string.Equals(parsedRequestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequestUri);
        }

        var clientId = await parameterReader.GetParameterAsync(
            request,
            OpenIddictConstants.Parameters.ClientId,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequest);
        }

        var application = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null)
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequest);
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applicationManager.PopulateAsync(descriptor, application, cancellationToken);

        if (!IsRequestUriRegistered(descriptor, parsedRequestUri.AbsoluteUri))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequestUri);
        }

        var requestObject = await FetchRequestObjectAsync(parsedRequestUri, cancellationToken);
        if (string.IsNullOrWhiteSpace(requestObject))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequestUri);
        }

        if (!requestObjectParser.TryParseUnsigned(requestObject, out var requestParameters))
        {
            return RequestObjectByReferenceResolutionResult.Failure(OpenIddictConstants.Errors.InvalidRequestObject);
        }

        return RequestObjectByReferenceResolutionResult.Success(requestParameters);
    }

    private async Task<string?> FetchRequestObjectAsync(Uri requestUri, CancellationToken cancellationToken)
    {
        try
        {
            var fetchUri = new UriBuilder(requestUri)
            {
                Fragment = string.Empty
            }.Uri;

            var client = httpClientFactory.CreateClient(nameof(RequestObjectByReferenceResolver));
            client.Timeout = TimeSpan.FromSeconds(
                Math.Clamp(compatibilityOptions.Value.RequestUriFetchTimeoutSeconds, 1, 60));

            using var response = await client.GetAsync(fetchUri, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            return string.IsNullOrWhiteSpace(body) ? null : body.Trim();
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (TaskCanceledException)
        {
            return null;
        }
    }

    private static bool IsRequestUriRegistered(OpenIddictApplicationDescriptor descriptor, string requestUri)
    {
        if (!descriptor.Properties.TryGetValue(OpenIdClientRegistrationPropertyNames.RequestUris, out var propertyValue) ||
            propertyValue.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var entry in propertyValue.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var registered = entry.GetString();
            if (string.IsNullOrWhiteSpace(registered))
            {
                continue;
            }

            if (string.Equals(registered, requestUri, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
