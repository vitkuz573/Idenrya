using System.Text;
using System.Text.Json;
using Idenrya.Server.Data;
using Idenrya.Server.Models;
using Idenrya.Server.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

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
        options.SetIntrospectionEndpointUris("/connect/introspect");
        options.SetRevocationEndpointUris("/connect/revocation");
        options.SetEndSessionEndpointUris("/connect/logout");

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
            .EnableEndSessionEndpointPassthrough()
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

app.Use(async (context, next) =>
{
    if (!context.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    var requestObject = await GetParameterAsync(context.Request, OpenIddictConstants.Parameters.Request);
    var requestUri = await GetParameterAsync(context.Request, OpenIddictConstants.Parameters.RequestUri);
    if (string.IsNullOrWhiteSpace(requestObject) && string.IsNullOrWhiteSpace(requestUri))
    {
        await next();
        return;
    }

    var appManager = context.RequestServices.GetRequiredService<IOpenIddictApplicationManager>();

    if (!string.IsNullOrWhiteSpace(requestUri))
    {
        var requestUriErrorLocation = await BuildAuthorizationErrorRedirectUriAsync(
            context.Request,
            appManager,
            OpenIddictConstants.Errors.RequestUriNotSupported);
        if (!string.IsNullOrWhiteSpace(requestUriErrorLocation))
        {
            context.Response.Redirect(requestUriErrorLocation);
            return;
        }

        await next();
        return;
    }

    if (string.IsNullOrWhiteSpace(requestObject))
    {
        await next();
        return;
    }

    if (!TryExtractUnsignedRequestObjectParameters(requestObject, out var requestParameters))
    {
        var invalidRequestObjectLocation = await BuildAuthorizationErrorRedirectUriAsync(
            context.Request,
            appManager,
            OpenIddictConstants.Errors.InvalidRequestObject);
        if (!string.IsNullOrWhiteSpace(invalidRequestObjectLocation))
        {
            context.Response.Redirect(invalidRequestObjectLocation);
            return;
        }

        await next();
        return;
    }

    var merged = await BuildMergedAuthorizationParametersAsync(context.Request, requestParameters);
    var rewritten = QueryHelpers.AddQueryString($"{context.Request.PathBase}{context.Request.Path}", merged);
    context.Response.Redirect(rewritten);
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static async Task<string?> GetParameterAsync(HttpRequest request, string name)
{
    var queryValue = request.Query[name].ToString();
    if (!string.IsNullOrWhiteSpace(queryValue))
    {
        return queryValue;
    }

    if (!request.HasFormContentType)
    {
        return null;
    }

    var formValue = (await request.ReadFormAsync())[name].ToString();
    return string.IsNullOrWhiteSpace(formValue) ? null : formValue;
}

static async Task<string?> BuildAuthorizationErrorRedirectUriAsync(
    HttpRequest request,
    IOpenIddictApplicationManager appManager,
    string error)
{
    var clientId = await GetParameterAsync(request, OpenIddictConstants.Parameters.ClientId);
    var redirectUri = await GetParameterAsync(request, OpenIddictConstants.Parameters.RedirectUri);
    if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
    {
        return null;
    }

    var application = await appManager.FindByClientIdAsync(clientId);
    if (application is null)
    {
        return null;
    }

    var registeredRedirectUris = await appManager.GetRedirectUrisAsync(application);
    if (!registeredRedirectUris.Contains(redirectUri, StringComparer.Ordinal))
    {
        return null;
    }

    var responseParameters = new Dictionary<string, string?>(StringComparer.Ordinal)
    {
        [OpenIddictConstants.Parameters.Error] = error
    };

    var state = await GetParameterAsync(request, OpenIddictConstants.Parameters.State);
    if (!string.IsNullOrWhiteSpace(state))
    {
        responseParameters[OpenIddictConstants.Parameters.State] = state;
    }

    return QueryHelpers.AddQueryString(redirectUri, responseParameters);
}

static async Task<List<KeyValuePair<string, string?>>> BuildMergedAuthorizationParametersAsync(
    HttpRequest request,
    IReadOnlyDictionary<string, string?> requestParameters)
{
    var merged = new List<KeyValuePair<string, string?>>();

    foreach (var pair in request.Query)
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

    if (request.HasFormContentType)
    {
        var form = await request.ReadFormAsync();
        foreach (var pair in form)
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
    }

    foreach (var parameter in requestParameters)
    {
        merged.RemoveAll(pair => pair.Key.Equals(parameter.Key, StringComparison.Ordinal));
        merged.Add(new KeyValuePair<string, string?>(parameter.Key, parameter.Value));
    }

    return merged;
}

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
