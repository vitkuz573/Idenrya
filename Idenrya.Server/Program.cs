using System.Text;
using System.Text.Json;
using Idenrya.Server.Data;
using Idenrya.Server.Models;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ConformanceOptions>(
    builder.Configuration.GetSection(ConformanceOptions.SectionName));

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=idenrya.db");
    options.UseOpenIddict();
});

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 3;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/account/login";
    options.AccessDeniedPath = "/account/login";
});

builder.Services.AddControllersWithViews();

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        var issuer = builder.Configuration[$"{ConformanceOptions.SectionName}:Issuer"];
        if (!string.IsNullOrWhiteSpace(issuer))
        {
            options.SetIssuer(new Uri(issuer));
        }

        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.SetUserInfoEndpointUris("/connect/userinfo");

        options.AllowAuthorizationCodeFlow();
        options.AllowRefreshTokenFlow();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Address,
            OpenIddictConstants.Scopes.Phone,
            OpenIddictConstants.Scopes.OfflineAccess);

        options.AddDevelopmentEncryptionCertificate();
        options.AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough()
            .EnableStatusCodePagesIntegration();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.EnsureCreatedAsync();
    await SeedData.InitializeAsync(scope.ServiceProvider);
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseStatusCodePagesWithReExecute("/error");

app.Use(async (context, next) =>
{
    if (!context.Request.Path.Equals("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    var originalBody = context.Response.Body;
    await using var buffer = new MemoryStream();
    context.Response.Body = buffer;

    await next();

    context.Response.Body = originalBody;
    buffer.Position = 0;

    if (context.Response.StatusCode != StatusCodes.Status200OK ||
        context.Response.ContentType is null ||
        !context.Response.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
    {
        await buffer.CopyToAsync(originalBody);
        return;
    }

    using var document = await JsonDocument.ParseAsync(buffer);
    await using var output = new MemoryStream();
    await using (var writer = new Utf8JsonWriter(output))
    {
        writer.WriteStartObject();

        var replaced = false;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.NameEquals("request_parameter_supported"))
            {
                writer.WriteBoolean("request_parameter_supported", true);
                replaced = true;
                continue;
            }

            property.WriteTo(writer);
        }

        if (!replaced)
        {
            writer.WriteBoolean("request_parameter_supported", true);
        }

        writer.WriteEndObject();
    }

    context.Response.ContentLength = output.Length;
    output.Position = 0;
    await output.CopyToAsync(originalBody);
});

// Handle request objects without modifying the conformance suite.
app.Use(async (context, next) =>
{
    if (!context.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    var hasRequestObject = context.Request.Query.ContainsKey(OpenIddictConstants.Parameters.Request) ||
                           context.Request.Query.ContainsKey(OpenIddictConstants.Parameters.RequestUri);
    if (!hasRequestObject)
    {
        await next();
        return;
    }

    var options = context.RequestServices.GetRequiredService<IOptions<ConformanceOptions>>().Value;
    var redirectUri = context.Request.Query[OpenIddictConstants.Parameters.RedirectUri].ToString();
    var knownRedirectUri = options.GetKnownRedirectUris().Contains(redirectUri, StringComparer.Ordinal);

    if (!knownRedirectUri)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "text/html; charset=UTF-8";
        await context.Response.WriteAsync(
            """
            <!doctype html>
            <html lang="en">
            <head><meta charset="utf-8"><title>Idenrya Error</title></head>
            <body><h1>oops! something went wrong</h1></body>
            </html>
            """);
        return;
    }

    if (context.Request.Query.ContainsKey(OpenIddictConstants.Parameters.RequestUri))
    {
        var location = QueryHelpers.AddQueryString(
            redirectUri,
            OpenIddictConstants.Parameters.Error,
            OpenIddictConstants.Errors.RequestUriNotSupported);

        context.Response.Redirect(location);
        return;
    }

    if (!context.Request.Query.TryGetValue(OpenIddictConstants.Parameters.Request, out var requestObjects) ||
        string.IsNullOrWhiteSpace(requestObjects))
    {
        await next();
        return;
    }

    if (!TryExtractUnsignedRequestObjectParameters(requestObjects.ToString(), out var requestParameters))
    {
        var invalidRequestLocation = QueryHelpers.AddQueryString(
            redirectUri,
            OpenIddictConstants.Parameters.Error,
            OpenIddictConstants.Errors.InvalidRequestObject);

        context.Response.Redirect(invalidRequestLocation);
        return;
    }

    var merged = new List<KeyValuePair<string, string?>>();
    foreach (var pair in context.Request.Query)
    {
        if (pair.Key.Equals(OpenIddictConstants.Parameters.Request, StringComparison.Ordinal) ||
            pair.Key.Equals(OpenIddictConstants.Parameters.RequestUri, StringComparison.Ordinal))
        {
            continue;
        }

        foreach (var value in pair.Value)
        {
            merged.Add(new KeyValuePair<string, string?>(pair.Key, value));
        }
    }

    foreach (var parameter in requestParameters)
    {
        merged.RemoveAll(pair => pair.Key.Equals(parameter.Key, StringComparison.Ordinal));
        merged.Add(new KeyValuePair<string, string?>(parameter.Key, parameter.Value));
    }

    var rewritten = QueryHelpers.AddQueryString($"{context.Request.PathBase}{context.Request.Path}", merged);
    context.Response.Redirect(rewritten);
    return;
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static bool TryExtractUnsignedRequestObjectParameters(
    string requestObject,
    out Dictionary<string, string?> parameters)
{
    parameters = new Dictionary<string, string?>(StringComparer.Ordinal);

    var segments = requestObject.Split('.');
    if (segments.Length != 3 || !string.IsNullOrEmpty(segments[2]))
    {
        return false;
    }

    try
    {
        var headerJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(segments[0]));
        using var headerDoc = JsonDocument.Parse(headerJson);
        if (!headerDoc.RootElement.TryGetProperty("alg", out var alg) ||
            !string.Equals(alg.GetString(), "none", StringComparison.Ordinal))
        {
            return false;
        }

        var payloadJson = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(segments[1]));
        using var payloadDoc = JsonDocument.Parse(payloadJson);

        foreach (var property in payloadDoc.RootElement.EnumerateObject())
        {
            parameters[property.Name] = property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number => property.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Array => string.Join(" ", property.Value.EnumerateArray()
                    .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.GetRawText())
                    .Where(static value => !string.IsNullOrWhiteSpace(value))),
                JsonValueKind.Null => null,
                _ => property.Value.GetRawText()
            };
        }

        return true;
    }
    catch (FormatException)
    {
        return false;
    }
    catch (JsonException)
    {
        return false;
    }
}
