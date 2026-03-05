using Idenrya.Server.Data;
using Idenrya.Server.Models;
using Idenrya.Server.Options;
using Idenrya.Server.Services.OpenId;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Idenrya.Server.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIdenryaIdentityProvider(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<ConformanceOptions>(
            configuration.GetSection(ConformanceOptions.SectionName));
        services.Configure<OpenIdProviderCompatibilityOptions>(
            configuration.GetSection(OpenIdProviderCompatibilityOptions.SectionName));

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseSqlite(configuration.GetConnectionString("DefaultConnection") ?? "Data Source=idenrya.db");
            options.UseOpenIddict();
        });

        services
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

        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/account/login";
            options.AccessDeniedPath = "/account/login";
        });

        services.AddControllersWithViews();
        services.AddOpenIddictServer(configuration);

        services.AddScoped<IHttpRequestParameterReader, HttpRequestParameterReader>();
        services.AddScoped<IRequestObjectParser, RequestObjectParser>();
        services.AddScoped<IAuthorizationErrorRedirectUriBuilder, AuthorizationErrorRedirectUriBuilder>();
        services.AddScoped<IAuthorizationRequestParameterMerger, AuthorizationRequestParameterMerger>();
        services.AddScoped<IAuthorizationRequestObjectResolver, AuthorizationRequestObjectResolver>();

        return services;
    }

    private static void AddOpenIddictServer(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                var issuer = configuration[$"{ConformanceOptions.SectionName}:Issuer"];
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
    }
}
