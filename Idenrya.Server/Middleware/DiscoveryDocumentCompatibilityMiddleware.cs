using System.Text.Json;
using Idenrya.Server.Models;
using Idenrya.Server.Options;
using Idenrya.Server.Services;
using Microsoft.Extensions.Options;

namespace Idenrya.Server.Middleware;

public sealed class DiscoveryDocumentCompatibilityMiddleware(RequestDelegate next)
{
    private const string DiscoveryEndpointPath = "/.well-known/openid-configuration";

    public async Task InvokeAsync(
        HttpContext context,
        IOptions<OpenIdProviderCompatibilityOptions> options,
        IOptions<IdentityProviderOptions> identityProviderOptions,
        IIdentityProviderScopeService scopeService)
    {
        var compatibilityOptions = options.Value;
        var dynamicClientRegistrationOptions = identityProviderOptions.Value.DynamicClientRegistration;
        var dynamicRegistrationEnabled = dynamicClientRegistrationOptions.Enabled;
        var allowUnsignedIdTokens = dynamicClientRegistrationOptions.AllowUnsignedIdTokens;
        if (!context.Request.Path.Equals(DiscoveryEndpointPath, StringComparison.OrdinalIgnoreCase) ||
            (!compatibilityOptions.RewriteDiscoveryRequestParameterSupported &&
             !compatibilityOptions.RewriteDiscoveryScopesSupported &&
             !compatibilityOptions.RewriteDiscoveryRequestUriParameterSupported &&
             !allowUnsignedIdTokens &&
             (!compatibilityOptions.RewriteDiscoveryRegistrationEndpoint || !dynamicRegistrationEnabled)))
        {
            await next(context);
            return;
        }

        var originalBody = context.Response.Body;
        await using var buffer = new MemoryStream();
        context.Response.Body = buffer;

        try
        {
            await next(context);

            if (!IsJsonSuccessResponse(context.Response))
            {
                buffer.Position = 0;
                await buffer.CopyToAsync(originalBody, context.RequestAborted);
                return;
            }

            buffer.Position = 0;
            try
            {
                using var document = await JsonDocument.ParseAsync(buffer, cancellationToken: context.RequestAborted);
                var supportedScopes = compatibilityOptions.RewriteDiscoveryScopesSupported
                    ? await scopeService.GetSupportedScopesAsync(context.RequestAborted)
                    : [];
                var registrationEndpoint = compatibilityOptions.RewriteDiscoveryRegistrationEndpoint &&
                                           dynamicRegistrationEnabled
                    ? BuildRegistrationEndpointUri(document.RootElement, context.Request)
                    : null;
                var requestUriParameterSupported = compatibilityOptions.RewriteDiscoveryRequestUriParameterSupported
                    ? (bool?)!compatibilityOptions.RejectRequestUriParameter
                    : null;

                await using var output = new MemoryStream();
                await using (var writer = new Utf8JsonWriter(output))
                {
                    writer.WriteStartObject();

                    var replacedRequestParameterSupported = false;
                    var replacedScopesSupported = false;
                    var replacedRegistrationEndpoint = false;
                    var replacedRequestUriParameterSupported = false;
                    var replacedIdTokenSigningAlgorithms = false;

                    foreach (var property in document.RootElement.EnumerateObject())
                    {
                        if (compatibilityOptions.RewriteDiscoveryRequestParameterSupported &&
                            property.NameEquals("request_parameter_supported"))
                        {
                            writer.WriteBoolean("request_parameter_supported", true);
                            replacedRequestParameterSupported = true;
                            continue;
                        }

                        if (compatibilityOptions.RewriteDiscoveryScopesSupported &&
                            property.NameEquals("scopes_supported"))
                        {
                            WriteScopesSupported(writer, supportedScopes);
                            replacedScopesSupported = true;
                            continue;
                        }

                        if (requestUriParameterSupported.HasValue &&
                            property.NameEquals("request_uri_parameter_supported"))
                        {
                            writer.WriteBoolean("request_uri_parameter_supported", requestUriParameterSupported.Value);
                            replacedRequestUriParameterSupported = true;
                            continue;
                        }

                        if (registrationEndpoint is not null &&
                            property.NameEquals("registration_endpoint"))
                        {
                            writer.WriteString("registration_endpoint", registrationEndpoint);
                            replacedRegistrationEndpoint = true;
                            continue;
                        }

                        if (allowUnsignedIdTokens &&
                            property.NameEquals("id_token_signing_alg_values_supported"))
                        {
                            WriteIdTokenSigningAlgorithms(writer, property.Value);
                            replacedIdTokenSigningAlgorithms = true;
                            continue;
                        }

                        property.WriteTo(writer);
                    }

                    if (compatibilityOptions.RewriteDiscoveryRequestParameterSupported &&
                        !replacedRequestParameterSupported)
                    {
                        writer.WriteBoolean("request_parameter_supported", true);
                    }

                    if (compatibilityOptions.RewriteDiscoveryScopesSupported && !replacedScopesSupported)
                    {
                        WriteScopesSupported(writer, supportedScopes);
                    }

                    if (requestUriParameterSupported.HasValue && !replacedRequestUriParameterSupported)
                    {
                        writer.WriteBoolean("request_uri_parameter_supported", requestUriParameterSupported.Value);
                    }

                    if (registrationEndpoint is not null && !replacedRegistrationEndpoint)
                    {
                        writer.WriteString("registration_endpoint", registrationEndpoint);
                    }

                    if (allowUnsignedIdTokens && !replacedIdTokenSigningAlgorithms)
                    {
                        writer.WritePropertyName("id_token_signing_alg_values_supported");
                        writer.WriteStartArray();
                        writer.WriteStringValue("RS256");
                        writer.WriteStringValue("none");
                        writer.WriteEndArray();
                    }

                    writer.WriteEndObject();
                }

                context.Response.ContentLength = output.Length;
                output.Position = 0;
                await output.CopyToAsync(originalBody, context.RequestAborted);
            }
            catch (JsonException)
            {
                buffer.Position = 0;
                await buffer.CopyToAsync(originalBody, context.RequestAborted);
            }
        }
        finally
        {
            context.Response.Body = originalBody;
        }
    }

    private static bool IsJsonSuccessResponse(HttpResponse response)
    {
        return response.StatusCode == StatusCodes.Status200OK &&
               response.ContentType is not null &&
               response.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static void WriteScopesSupported(Utf8JsonWriter writer, IReadOnlyList<string> supportedScopes)
    {
        writer.WritePropertyName("scopes_supported");
        writer.WriteStartArray();
        foreach (var scope in supportedScopes)
        {
            writer.WriteStringValue(scope);
        }

        writer.WriteEndArray();
    }

    private static void WriteIdTokenSigningAlgorithms(Utf8JsonWriter writer, JsonElement existing)
    {
        var values = new List<string>();
        if (existing.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in existing.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var value = entry.GetString();
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                values.Add(value);
            }
        }

        if (!values.Contains("RS256", StringComparer.Ordinal))
        {
            values.Add("RS256");
        }

        if (!values.Contains("none", StringComparer.Ordinal))
        {
            values.Add("none");
        }

        writer.WritePropertyName("id_token_signing_alg_values_supported");
        writer.WriteStartArray();
        foreach (var value in values.Distinct(StringComparer.Ordinal))
        {
            writer.WriteStringValue(value);
        }
        writer.WriteEndArray();
    }

    private static string BuildRegistrationEndpointUri(JsonElement discoveryDocument, HttpRequest request)
    {
        if (discoveryDocument.TryGetProperty("issuer", out var issuerElement) &&
            issuerElement.ValueKind == JsonValueKind.String)
        {
            var issuer = issuerElement.GetString();
            if (!string.IsNullOrWhiteSpace(issuer) &&
                Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
            {
                var path = issuerUri.AbsolutePath.TrimEnd('/');
                var builder = new UriBuilder(issuerUri)
                {
                    Path = $"{path}/connect/register"
                };

                return builder.Uri.AbsoluteUri;
            }
        }

        return new Uri($"{request.Scheme}://{request.Host}{request.PathBase}/connect/register").AbsoluteUri;
    }
}
