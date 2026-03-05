using System.Text.Json;
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
        IIdentityProviderScopeService scopeService)
    {
        var compatibilityOptions = options.Value;
        if (!context.Request.Path.Equals(DiscoveryEndpointPath, StringComparison.OrdinalIgnoreCase) ||
            (!compatibilityOptions.RewriteDiscoveryRequestParameterSupported &&
             !compatibilityOptions.RewriteDiscoveryScopesSupported))
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

                await using var output = new MemoryStream();
                await using (var writer = new Utf8JsonWriter(output))
                {
                    writer.WriteStartObject();

                    var replacedRequestParameterSupported = false;
                    var replacedScopesSupported = false;

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
}
